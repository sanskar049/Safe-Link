import sqlite3
import re
import ipaddress
import math
import csv
import io
import socket
import html as htmlmod
import os
from datetime import datetime
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher

from flask import Flask, render_template, request, jsonify, Response
from werkzeug.exceptions import HTTPException
import requests

app = Flask(__name__)
DB = "safelink.db"

BRANDS = [
    "google", "facebook", "instagram", "microsoft", "apple", "amazon",
    "paypal", "paytm", "phonepe", "flipkart", "netflix", "whatsapp",
    "linkedin", "sbi", "hdfcbank", "icicibank", "axisbank"
]

OFFICIAL_DOMAINS = {
    "google": {"google.com", "www.google.com"},
    "facebook": {"facebook.com", "www.facebook.com"},
    "instagram": {"instagram.com", "www.instagram.com"},
    "microsoft": {"microsoft.com", "www.microsoft.com"},
    "apple": {"apple.com", "www.apple.com"},
    "amazon": {"amazon.com", "amazon.in", "www.amazon.com", "www.amazon.in"},
    "paypal": {"paypal.com", "www.paypal.com"},
    "paytm": {"paytm.com", "www.paytm.com"},
    "phonepe": {"phonepe.com", "www.phonepe.com"},
    "flipkart": {"flipkart.com", "www.flipkart.com"},
    "netflix": {"netflix.com", "www.netflix.com"},
    "whatsapp": {"whatsapp.com", "www.whatsapp.com"},
    "linkedin": {"linkedin.com", "www.linkedin.com"},
    "sbi": {"sbi.co.in", "www.sbi.co.in"},
    "hdfcbank": {"hdfcbank.com", "www.hdfcbank.com"},
    "icicibank": {"icicibank.com", "www.icicibank.com"},
    "axisbank": {"axisbank.com", "www.axisbank.com"},
}

PHISHING_WORDS = {
    "login": 2, "log-in": 2, "signin": 2, "sign-in": 2,
    "verify": 2, "verification": 2, "password": 3, "account": 2,
    "secure": 1, "update": 2, "confirm": 2, "recover": 2,
    "suspended": 3, "urgent": 2, "wallet": 2, "payment": 2,
    "bank": 2, "otp": 2, "authenticate": 2, "auth": 1,
    "claim": 1, "bonus": 1, "gift": 1
}

SUSPICIOUS_TLDS = {"xyz": 2, "top": 2, "click": 2, "work": 1, "zip": 2, "tk": 2, "ml": 2, "ga": 2, "cf": 2, "gq": 2}

FANTASY_DOMAIN_TERMS = [
    "dream11", "my11circle", "mplfantasy", "vision11", "fantasyakhada",
    "fantasycricket", "fantasysports", "myteam11", "halaplay"
]
GAMBLING_TERMS = [
    "casino", "casinos", "betting", "sportsbook", "sports-betting",
    "gambling", "gamble", "poker", "slots", "roulette", "blackjack",
    "jackpot", "lottery", "wager", "bookmaker", "bookie", "bet365",
    "betway", "parimatch", "1xbet", "betfair", "draftkings", "fanduel",
    "stake", "22bet", "melbet", "dafabet", "10bet", "888casino"
]
PIRACY_DOMAIN_TERMS = [
    "netmirror", "watch-online", "watchfree", "downloadmovie",
    "download-movie", "camrip", "webrip", "bluray", "dual-audio",
    "torrent", "magnet", "pirated", "piracy", "free-streaming"
]


def conn():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


def init_db():
    c = conn()
    c.execute("PRAGMA journal_mode=WAL")
    c.execute(
        "CREATE TABLE IF NOT EXISTS scans("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "url TEXT,status TEXT,score INTEGER,confidence REAL,"
        "domain_status TEXT,scanned_at TEXT)"
    )
    c.commit()
    c.close()


def entropy(value):
    if not value:
        return 0.0
    n = len(value)
    return -sum((value.count(ch) / n) * math.log2(value.count(ch) / n)
                for ch in set(value))


def safe_int(value):
    try:
        return int(str(value).split()[0])
    except (ValueError, TypeError, IndexError):
        return None


def host_is_official(host, brand):
    host = (host or "").lower().rstrip(".")
    return host in OFFICIAL_DOMAINS.get(brand, set())


def domain_labels(host):
    return [x for x in (host or "").lower().split(".") if x]


def detect_domain_brand_risk(host):
    """Return brands that look like impersonation, not ordinary brand mentions."""
    labels = domain_labels(host)
    found = []
    suspicious_context = re.compile(
        r"(login|signin|sign-in|verify|secure|account|support|update|"
        r"auth|payment|wallet|bonus|claim|official|help)",
        re.I
    )
    for brand in BRANDS:
        if host_is_official(host, brand):
            continue
        exact_label = brand in labels
        embedded = brand in host
        # A brand used as a hostname label on an unrelated registrable domain
        # is already suspicious; authentication words make the signal stronger.
        if exact_label and not host.endswith("." + brand + ".com") and (
            suspicious_context.search(host) or len(labels) > 2
        ):
            found.append(brand)
        elif embedded and any(
            token in host for token in (f"{brand}-", f"-{brand}", f"{brand}.", f".{brand}")
        ) and suspicious_context.search(host):
            found.append(brand)
    return list(dict.fromkeys(found))


def detect_typosquatting(host):
    labels = domain_labels(host)
    if not labels:
        return []
    registrable = labels[-2] if len(labels) >= 2 else labels[0]
    found = []
    for brand in BRANDS:
        if host_is_official(host, brand):
            continue
        if abs(len(registrable) - len(brand)) <= 2:
            ratio = SequenceMatcher(None, registrable, brand).ratio()
            if 0.72 <= ratio < 1.0:
                found.append(brand)
    return list(dict.fromkeys(found))


def reachability(url, host):
    try:
        socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return {
            "dns": "Not resolved",
            "http": "Not checked",
            "reachable": False,
            "detail": "The domain could not be resolved by DNS."
        }

    try:
        r = requests.get(
            url,
            allow_redirects=True,
            timeout=8,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 SafeLink/1.0"}
        )
        code = r.status_code
        final_url = r.url
        r.close()
        return {
            "dns": "Resolved",
            "http": str(code),
            "reachable": True,
            "detail": f"Server responded with HTTP {code}.",
            "final_url": final_url
        }
    except requests.RequestException:
        return {
            "dns": "Resolved",
            "http": "No response",
            "reachable": False,
            "detail": "The domain resolved, but the server did not return a response."
        }


def extract_visible_text(page):
    text = re.sub(r"<script[^>]*>.*?</script>", " ", page, flags=re.I | re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<noscript[^>]*>.*?</noscript>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", htmlmod.unescape(text)).strip()


def analyze_page_content(page, title, host):
    visible = extract_visible_text(page)
    metadata = f"{visible} {title} {host}".lower()

    def count(pattern):
        return len(re.findall(pattern, metadata, re.I))

    result = {
        "_raw_html": page,
        "reachable": True,
        "title": title[:200],
        "signals": [],
        "brand_impersonation": [],
        "categories": [],
        "forms": len(re.findall(r"<form\b", page, re.I)),
        "password_fields": len(re.findall(r'<input[^>]+type=["\']?password', page, re.I)),
        "payment_signals": 0,
        "policy_signals": 0,
        "discount_signals": 0,
        "phishing_signals": 0,
        "status_code": "200",
        "content_source": "HTTP",
        "detail": "Public webpage content was analyzed."
    }

    gambling = count(r"\b(casino|gambling|gamble|betting|sportsbook|sports[- ]?betting|"
                     r"slots?|jackpot|roulette|blackjack|poker|lottery|wager|"
                     r"bookmaker|bookie|bet now|bet slip|odds)\b")
    fantasy = count(r"\b(fantasy sports?|fantasy cricket|fantasy football|fantasy league|"
                    r"paid contest|cash contest|real money|entry fee|prize pool|"
                    r"join contest|play and win|play & win|dream team)\b")
    shopping = count(r"\b(add to cart|buy now|shop now|checkout|cart|order now|"
                     r"shipping|delivery|refund|return policy|track order)\b")
    payment = count(r"\b(upi|payment|pay now|credit card|debit card|bank transfer|"
                    r"net banking|wallet|razorpay|stripe|cash on delivery|cod|"
                    r"entry fee|deposit|withdrawal)\b")
    discounts = count(r"\b(\d{2,3}\s*%\s*(off|discount)|flash sale|mega sale|"
                      r"limited time|lowest price|huge discount|clearance sale)\b")
    piracy = count(r"\b(movie|movies|web series|webseries|watch online|watch free|"
                   r"download movie|download movies|1080p|720p|camrip|webrip|"
                   r"bluray|dual audio|torrent|magnet|pirated|piracy|free streaming)\b")

    phishing_context = count(
        r"\b(login|log in|signin|sign in|verify|verification|password|account|"
        r"secure|update|confirm|recover|suspended|urgent|otp|authenticate|"
        r"payment|wallet|bank|customer support)\b"
    )
    result["phishing_signals"] = phishing_context
    result["payment_signals"] = payment
    result["discount_signals"] = discounts
    result["policy_signals"] = count(
        r"\b(privacy policy|terms and conditions|terms of service|refund policy|"
        r"return policy|contact us|about us)\b"
    )

    if gambling:
        result["categories"].append("Gambling / betting")
        result["signals"].append("Gambling/betting content detected")
    if fantasy >= 2:
        result["categories"].append("Fantasy sports / paid contests")
        result["signals"].append("Fantasy/paid-contest content detected")
    if shopping >= 2:
        result["categories"].append("E-commerce")
        result["signals"].append("Shopping/e-commerce content detected")
    if piracy >= 3:
        result["categories"].append("Potentially unauthorized streaming / piracy")
        result["signals"].append("Multiple streaming/piracy indicators detected")
    if payment >= 2:
        result["signals"].append("Payment-related content detected")
    if discounts:
        result["signals"].append("Discount/sale language detected")

    # Strong impersonation requires a brand + login/security context.
    page_lower = visible.lower()
    title_lower = title.lower()
    context_re = re.compile(
        r"\b(login|log in|signin|sign in|account|password|verify|verification|"
        r"secure|payment|checkout|wallet|otp|bank|customer support)\b", re.I
    )
    suspicious_host_re = re.compile(
        r"(login|signin|verify|secure|account|support|update|bonus|offer|claim|wallet|auth)",
        re.I
    )
    labels = domain_labels(host)

    for brand in BRANDS:
        if host_is_official(host, brand):
            continue
        brand_in_host = brand in labels or re.search(
            rf"(^|[.\-_]){re.escape(brand)}([.\-_]|$)", host, re.I
        )
        brand_in_page = bool(re.search(rf"\b{re.escape(brand)}\b", page_lower))
        brand_in_title = bool(re.search(rf"\b{re.escape(brand)}\b", title_lower))
        if (
            (brand_in_host and suspicious_host_re.search(host))
            or (brand_in_page and brand_in_title and context_re.search(visible))
            or (brand_in_host and brand_in_page and context_re.search(visible))
        ):
            result["brand_impersonation"].append(brand)

    if result["brand_impersonation"]:
        result["signals"].append(
            "Possible brand impersonation: " +
            ", ".join(result["brand_impersonation"][:4])
        )

    return result, len(visible)


def page_analysis(url):
    result = {
        "reachable": False, "title": "", "signals": [],
        "brand_impersonation": [], "categories": [],
        "forms": 0, "password_fields": 0, "payment_signals": 0,
        "policy_signals": 0, "discount_signals": 0, "phishing_signals": 0,
        "status_code": "Not checked",
        "detail": "Page content was not checked.",
        "blocked": False,
        "content_source": "Not checked"
    }

    p = urlparse(url)
    host = (p.hostname or "").lower()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-IN,en;q=0.9"
    }

    domain_text = (host + " " + p.path).lower()
    domain_categories = []
    if any(x in domain_text for x in FANTASY_DOMAIN_TERMS):
        domain_categories.append("Fantasy sports / paid contests")
    if any(x in domain_text for x in GAMBLING_TERMS):
        domain_categories.append("Gambling / betting")
    if any(x in domain_text for x in PIRACY_DOMAIN_TERMS):
        domain_categories.append("Potentially unauthorized streaming / piracy")
    result["categories"] = domain_categories

    try:
        r = requests.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=10,
            stream=True
        )
        code = r.status_code
        final_url = r.url
        final_host = (urlparse(final_url).hostname or "").lower()
        content_type = (r.headers.get("Content-Type") or "").lower()
        page = r.text[:700000]
        r.close()

        result["status_code"] = str(code)
        result["reachable"] = True

        title_match = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
        title = re.sub(
            r"\s+", " ", htmlmod.unescape(title_match.group(1))
        ).strip()[:200] if title_match else ""

        # A deep-link 404 can still have a working site root.
        if code == 404 and p.path not in ("", "/"):
            try:
                origin = f"{p.scheme}://{p.netloc}/"
                rr = requests.get(origin, headers=headers, allow_redirects=True, timeout=10)
                root_code = rr.status_code
                root_page = rr.text[:700000]
                root_url = rr.url
                if 200 <= root_code < 300 and len(root_page.strip()) >= 80:
                    root_title_match = re.search(r"<title[^>]*>(.*?)</title>", root_page, re.I | re.S)
                    root_title = re.sub(
                        r"\s+", " ", htmlmod.unescape(root_title_match.group(1))
                    ).strip()[:200] if root_title_match else title
                    analyzed, _ = analyze_page_content(root_page, root_title, (urlparse(root_url).hostname or "").lower())
                    analyzed["categories"] = list(dict.fromkeys(domain_categories + analyzed.get("categories", [])))
                    analyzed["status_code"] = str(root_code)
                    analyzed["content_source"] = "HTTP"
                    analyzed["detail"] = (
                        f"The requested path returned HTTP 404, but the site homepage "
                        f"responded with HTTP {root_code} and was analyzed."
                    )
                    return analyzed
                rr.close()
            except requests.RequestException:
                pass

        # Analyze actual readable HTML when we have it.
        if ("html" in content_type or "text/" in content_type) and len(page.strip()) >= 80:
            analyzed, _ = analyze_page_content(page, title, final_host)
            analyzed["categories"] = list(dict.fromkeys(domain_categories + analyzed.get("categories", [])))
            analyzed["status_code"] = str(code)
            analyzed["reachable"] = True
            if code in (401, 403, 429):
                analyzed["blocked"] = True
                analyzed["content_source"] = "Access restricted"
                analyzed["detail"] = (
                    f"The server returned HTTP {code}; some or all page content "
                    "may be restricted to automated scanners."
                )
            elif code >= 500:
                analyzed["content_source"] = "Server unavailable"
                analyzed["detail"] = f"The website returned HTTP {code}."
            elif code == 404:
                analyzed["content_source"] = "HTTP"
                analyzed["detail"] = "The requested webpage returned HTTP 404."
            return analyzed

        # Explicit availability states. These are not "URL/domain fallback" because
        # the server did respond and we know the HTTP result.
        if code in (401, 403, 429):
            result["blocked"] = True
            result["content_source"] = "Access restricted"
            result["detail"] = (
                f"The server returned HTTP {code}; the webpage could not be fully "
                "read by the scanner."
            )
        elif code == 404:
            result["content_source"] = "HTTP"
            result["detail"] = (
                "The requested webpage returned HTTP 404. The domain itself "
                "resolved, but this page could not be found."
            )
        elif code >= 500:
            result["content_source"] = "Server unavailable"
            result["detail"] = f"The server returned HTTP {code}; page analysis was unavailable."
        else:
            result["content_source"] = "HTTP"
            result["detail"] = "The server responded, but readable webpage content was limited."

        return result

    except requests.RequestException:
        # A true network/request failure, rather than a normal 403/404 response.
        result["content_source"] = "URL/domain fallback"
        result["detail"] = (
            "Page content could not be retrieved. URL, DNS and reputation "
            "checks were used instead."
        )
        result["blocked"] = True
        return result


def google_safe_browsing_check(url):
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    result = {
        "enabled": bool(api_key),
        "status": "Not configured" if not api_key else "Checking",
        "safe": None,
        "threats": [],
        "error": None
    }
    if not api_key:
        return result

    try:
        r = requests.get(
            "https://safebrowsing.googleapis.com/v5/urls:search",
            params=[("key", api_key), ("urls", url)],
            headers={"Accept": "application/json"},
            timeout=8
        )
        if r.status_code != 200:
            result["status"] = "API error"
            result["error"] = f"HTTP {r.status_code}"
            return result
        data = r.json()
        threats = data.get("threats", []) or []
        result["threats"] = [
            {"url": x.get("url", ""), "types": x.get("threatTypes", [])}
            for x in threats
        ]
        result["safe"] = not bool(threats)
        result["status"] = "Threat detected" if threats else "No known Google threat"
    except requests.RequestException as exc:
        result["status"] = "API unavailable"
        result["error"] = str(exc)[:160]
    except ValueError:
        result["status"] = "Invalid API response"
        result["error"] = "Google returned a non-JSON response"
    return result


def content_analysis_label(page):
    page = page or {}
    source = page.get("content_source", "")
    status = safe_int(page.get("status_code"))

    if source == "HTTP" and status is not None and 200 <= status < 300:
        return "Page content analyzed"
    if source in ("Access restricted", "403"):
        return f"Page access restricted (HTTP {status})" if status else "Page access restricted"
    if source in ("Server unavailable", "5xx"):
        return f"Server unavailable (HTTP {status})" if status else "Server unavailable"
    if status == 404:
        return "Page not found (HTTP 404)"
    if source == "URL/domain fallback":
        return "Page content unavailable — URL/domain checks used"
    if source == "HTTP":
        return "Page responded, but readable content was limited"
    if source == "Not checked":
        return "Page was not checked"
    return "Page could not be fully analyzed"


def calculate_confidence(reach, page, gsb, evidence_count):
    points = 0
    if reach.get("dns") in ("Resolved", "IP"):
        points += 20
    if reach.get("http") not in ("Not checked", "No response"):
        points += 20
    if page.get("content_source") == "HTTP" and safe_int(page.get("status_code")) and safe_int(page.get("status_code")) < 300:
        points += 30
    elif page.get("content_source") == "Access restricted":
        points += 10
    if page.get("categories") or page.get("signals") or page.get("brand_impersonation"):
        points += 10
    if gsb.get("enabled"):
        points += 20
    else:
        points += 5

    # More independent evidence means more confidence; inaccessible content limits it.
    points += min(10, evidence_count * 2)
    if page.get("content_source") in ("URL/domain fallback", "Server unavailable"):
        points = min(points, 62)
    return max(25, min(99, round(points)))


def risk_level(score):
    if score >= 80:
        return "Dangerous"
    if score >= 50:
        return "High Risk"
    if score >= 20:
        return "Suspicious"
    return "Low Risk"


def friendly_statuses(result):
    dns = result.get("domain_status", "")
    http = result.get("http_status", "")
    reachable = result.get("reachable", False)
    page = result.get("page", {}) or {}
    ps = safe_int(page.get("status_code"))

    if dns == "Not resolved":
        domain = (
            "Not resolved", "danger",
            "The domain could not be located through DNS.",
            dns
        )
    elif dns == "IP":
        domain = (
            "IP address", "warn",
            "The URL uses a numeric server address instead of a normal domain.",
            dns
        )
    else:
        domain = (
            "Found", "pass",
            "The website's domain address was successfully located.",
            dns
        )

    hs = safe_int(http)
    if hs == 403:
        server = (
            "Access restricted", "warn",
            "The server did not allow the scanner to access the page. This does not by itself mean the website is unsafe.",
            http
        )
    elif hs == 404:
        server = (
            "Page not found", "warn",
            "The server responded, but the requested path was not found.",
            http
        )
    elif hs is not None and 200 <= hs < 300:
        server = (
            "Responded", "pass",
            "The server returned a successful response.",
            http
        )
    elif hs is not None and 300 <= hs < 400:
        server = (
            "Redirected", "warn",
            "The server redirected the request to another address.",
            http
        )
    elif hs is not None and hs >= 500:
        server = (
            "Server unavailable", "warn",
            "The server reported a temporary server-side problem.",
            http
        )
    elif reachable:
        server = (
            "Responded", "pass",
            "The server responded to the scanner.",
            http
        )
    else:
        server = (
            "No response", "warn",
            "The domain resolved, but the server did not return a response.",
            http
        )

    if page.get("content_source") == "Access restricted" or ps == 403:
        page_ui = (
            "Access restricted", "warn",
            "The webpage blocked automated access, so content analysis was limited.",
            page.get("status_code", "")
        )
    elif ps == 404:
        page_ui = (
            "Page not found", "warn",
            "The requested webpage path returned HTTP 404.",
            page.get("status_code", "")
        )
    elif ps is not None and 200 <= ps < 300:
        page_ui = (
            "Loaded", "pass",
            "The webpage was successfully accessed for analysis.",
            page.get("status_code", "")
        )
    elif ps is not None and ps >= 500:
        page_ui = (
            "Unavailable", "warn",
            "The webpage could not be analyzed because the server returned an error.",
            page.get("status_code", "")
        )
    else:
        page_ui = (
            "Limited", "warn",
            "The webpage could not be fully checked.",
            page.get("status_code", "")
        )

    return {
        "domain": {"label": domain[0], "state": domain[1], "help": domain[2], "technical": domain[3]},
        "server": {"label": server[0], "state": server[1], "help": server[2], "technical": server[3]},
        "page": {"label": page_ui[0], "state": page_ui[1], "help": page_ui[2], "technical": page_ui[3]}
    }


def analyze_url(url):
    original = (url or "").strip()

    invalid = {
        "status": "Invalid URL",
        "invalid_url": True,
        "invalid_message": "Please enter a valid website address, such as https://example.com.",
        "score": 0,
        "confidence": 0,
        "reasons": [],
        "checks": [],
        "url": original,
        "domain_not_resolved": False
    }

    if not original:
        return invalid

    normalized = (
        original if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", original)
        else "https://" + original
    )

    try:
        p = urlparse(normalized)
        host = (p.hostname or "").lower().rstrip(".")
    except Exception:
        return invalid

    if (
        not host
        or any(ch.isspace() for ch in original)
        or (
            "." not in host
            and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)
        )
    ):
        return invalid

    try:
        is_ip = bool(ipaddress.ip_address(host))
    except ValueError:
        is_ip = False

    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    text = unquote(original.lower())
    score = 0
    reasons = []
    checks = []
    evidence = 0

    def add(points, reason, evidence_piece=True):
        nonlocal score, evidence
        score += points
        reasons.append(reason)
        if evidence_piece:
            evidence += 1

    # Reachability is an availability signal, not a direct malware signal.
    reach = (
        {"dns": "IP", "http": "Not checked", "reachable": False,
         "detail": "IP host; DNS resolution is not applicable."}
        if is_ip else reachability(normalized, host)
    )

    if reach["dns"] == "Not resolved":
        checks.append(("Domain / DNS", "danger", "Not resolved"))
        gsb = google_safe_browsing_check(normalized)
        page = {
            "reachable": False, "signals": [], "brand_impersonation": [],
            "categories": [], "forms": 0, "password_fields": 0,
            "payment_signals": 0, "policy_signals": 0, "discount_signals": 0,
            "phishing_signals": 0, "status_code": "Not checked",
            "content_source": "Not checked",
            "detail": "Page analysis was skipped because the domain did not resolve."
        }
        checks.append((
            "Google Safe Browsing",
            "pass" if gsb.get("enabled") and gsb.get("safe") else ("warn" if not gsb.get("enabled") else "danger"),
            "No known threat" if gsb.get("enabled") and gsb.get("safe") else (
                "Not configured" if not gsb.get("enabled") else "Threat detected"
            )
        ))
        result = {
            "status": "Domain Does Not Exist",
            "invalid_url": False,
            "domain_not_resolved": True,
            "score": 0,
            "confidence": 98,
            "reasons": [
                "The domain could not be resolved through DNS.",
                "The server and webpage could not be checked.",
                "A DNS failure does not prove that a website is malicious."
            ],
            "checks": checks,
            "host": host,
            "scheme": p.scheme,
            "url": original,
            "domain_status": "Not resolved",
            "http_status": "Not checked",
            "reachable": False,
            "reach_detail": "The domain could not be resolved by DNS.",
            "page": page,
            "content_analysis_label": "Page was not checked",
            "google_safe_browsing": gsb,
            "friendly_statuses": friendly_statuses({
                "domain_status": "Not resolved",
                "http_status": "Not checked",
                "reachable": False,
                "page": page
            })
        }
        return result

    evidence += 1
    checks.append(("Domain / DNS", "pass", "Resolved"))

    if p.scheme == "https":
        checks.append(("HTTPS", "pass", "Enabled"))
    else:
        add(3, "The website uses HTTP instead of HTTPS")
        checks.append(("HTTPS", "warn", "HTTP connection"))

    if is_ip:
        add(18, "A raw IP address is used instead of a normal domain")
    checks.append((
        "IP address",
        "danger" if is_ip else "pass",
        "Raw IP" if is_ip else "Normal domain"
    ))

    # URL structure signals.
    length = len(original)
    if length > 160:
        add(7, "Very long URL")
    elif length > 100:
        add(4, "Long URL")
    checks.append(("URL length", "warn" if length > 100 else "pass", f"{length} characters"))

    if "@" in original:
        add(15, "The @ symbol can hide the real destination")
    if original.count("//") > 1:
        add(6, "Extra // sequence suggests URL obfuscation")
    if "%" in original:
        add(2, "Percent-encoded characters are present")
    obfuscation = "danger" if "@" in original or original.count("//") > 1 else (
        "warn" if "%" in original else "pass"
    )
    checks.append(("Obfuscation", obfuscation, "Suspicious pattern" if obfuscation != "pass" else "None"))

    puny = "xn--" in host
    if puny:
        add(12, "Punycode/look-alike hostname detected")
    checks.append(("Look-alike", "danger" if puny else "pass", "Punycode" if puny else "None"))

    subs = max(0, len(parts) - 2)
    if subs >= 5:
        add(7, "Unusually many subdomains")
    elif subs >= 3:
        add(3, "Several subdomains")
    checks.append(("Subdomains", "warn" if subs >= 3 else "pass", str(subs)))

    hyphens = host.count("-")
    if hyphens >= 4:
        add(5, "Several hyphens in the hostname")
    elif hyphens >= 2:
        add(2, "Multiple hyphens in the hostname")
    checks.append(("Domain structure", "warn" if hyphens >= 2 else "pass", f"{hyphens} hyphens"))

    if tld in SUSPICIOUS_TLDS:
        add(SUSPICIOUS_TLDS[tld], f"Potentially abused TLD: .{tld}")
    checks.append(("TLD", "warn" if tld in SUSPICIOUS_TLDS else "pass", "." + tld if tld else "Unknown"))

    # Keyword points are deliberately capped. A keyword alone is weak evidence.
    keyword_points = sum(weight for word, weight in PHISHING_WORDS.items() if word in text)
    if keyword_points:
        add(min(8, keyword_points), "Phishing-related words found in the URL")
    checks.append(("Keywords", "warn" if keyword_points else "pass", f"{min(8, keyword_points)} weighted points"))

    domain_brand = detect_domain_brand_risk(host)
    typo = detect_typosquatting(host)

    if typo:
        add(min(18, 9 * len(typo)), "Possible typosquatting: " + ", ".join(typo[:3]))
    # Brand in a suspicious hostname is much stronger than an ordinary brand word.
    if domain_brand:
        add(min(24, 12 * len(domain_brand)),
            "Possible brand impersonation: " + ", ".join(domain_brand[:3]))
    checks.append((
        "Brand / typosquatting",
        "danger" if domain_brand or typo else "pass",
        ", ".join((domain_brand + typo)[:3]) if domain_brand or typo else "No obvious match"
    ))

    digits = sum(ch.isdigit() for ch in host)
    digit_ratio = digits / max(1, len(host))
    if digits >= 5 and digit_ratio > 0.25:
        add(4, "Unusually high digit ratio in hostname")
    checks.append(("Hostname complexity", "warn" if digits >= 5 and digit_ratio > 0.25 else "pass", f"{digits} digits"))

    params = len(re.findall(r"(^|&)[^=]+=", p.query or ""))
    path_len = len(p.path or "")
    if params >= 8:
        add(4, "Many query parameters")
    elif params >= 5:
        add(2, "Several query parameters")
    if path_len > 140:
        add(4, "Very long URL path")
    checks.append(("Path / query", "warn" if params >= 5 or path_len > 140 else "pass", f"{params} parameters"))

    ent = entropy(host)
    if ent > 4.3 and len(host) > 20:
        add(4, "High hostname randomness")
    checks.append(("Hostname randomness", "warn" if ent > 4.3 and len(host) > 20 else "pass", f"{ent:.2f} entropy"))

    # External reputation.
    gsb = google_safe_browsing_check(normalized)
    if gsb.get("safe") is False:
        threat_types = []
        for item in gsb.get("threats", []):
            threat_types.extend(item.get("types", []))
        threat_types = list(dict.fromkeys(threat_types))
        add(55, "Google Safe Browsing reports a known threat" +
            (f" ({', '.join(threat_types)})" if threat_types else ""))
    checks.append((
        "Google Safe Browsing",
        "danger" if gsb.get("safe") is False else ("pass" if gsb.get("enabled") else "warn"),
        "Threat detected" if gsb.get("safe") is False else (
            "No known threat" if gsb.get("enabled") else "Not configured"
        )
    ))

    # Page content. Classification is kept separate from security risk.
    page = page_analysis(normalized) if reach["dns"] != "Not resolved" else {
        "reachable": False, "signals": [], "brand_impersonation": [],
        "categories": [], "forms": 0, "password_fields": 0,
        "payment_signals": 0, "policy_signals": 0, "discount_signals": 0,
        "phishing_signals": 0, "status_code": "Not checked",
        "content_source": "Not checked",
        "detail": "Page analysis skipped because the domain did not resolve."
    }

    categories = page.get("categories", [])
    if categories:
        evidence += 1

    # Content/category risk is separate from malware/phishing risk, but it should not
    # disappear into a 0/100 "Low Risk" result. These modest weights make the result
    # informative without claiming that a category is inherently malicious.
    if "Potentially unauthorized streaming / piracy" in categories:
        add(15, "Website category shows multiple signals associated with potentially unauthorized streaming/piracy")
    elif "Gambling / betting" in categories:
        add(10, "Website category shows gambling/betting content")
    elif "Fantasy sports / paid contests" in categories:
        add(6, "Website category shows fantasy sports or paid-contest content")
    elif "E-commerce" in categories:
        add(4, "Website category shows e-commerce activity")

    page_brands = page.get("brand_impersonation", [])
    if page_brands:
        add(min(28, 14 * len(page_brands)),
            "Page content shows possible impersonation of " + ", ".join(page_brands[:3]))

    # Correlated phishing evidence is stronger than isolated keywords.
    phishing = page.get("phishing_signals", 0)
    password_fields = page.get("password_fields", 0)
    forms = page.get("forms", 0)
    payment_signals = page.get("payment_signals", 0)

    if password_fields and phishing >= 2:
        add(10, "Password/login form appears together with security-related language")
    if page_brands and (password_fields or phishing >= 2):
        add(14, "Brand impersonation is combined with a login/security context")
    if payment_signals >= 3 and (password_fields or phishing >= 3):
        add(8, "Payment activity is combined with account/security signals")

    # Scam language is meaningful only when several indicators occur together.
    raw_page = page.get("_raw_html", "")
    visible_page = extract_visible_text(raw_page).lower() if raw_page else ""
    scam_terms = len(re.findall(
        r"\b(guaranteed profit|you won|winner|claim reward|send money|"
        r"investment return|double your money|limited time|act now|"
        r"account suspended|verify immediately)\b",
        visible_page, re.I
    ))
    if scam_terms >= 2 and (payment_signals or phishing >= 2):
        add(10, "Multiple scam/urgent-action signals detected in page content")

    # Availability problems do not automatically increase cyber risk.
    http_code = safe_int(reach.get("http"))
    if http_code in (401, 403, 429):
        reasons.append(f"Page access was restricted by HTTP {http_code}; this is not treated as proof of maliciousness.")
    elif http_code == 404:
        reasons.append("The requested page returned HTTP 404; this is an availability issue, not proof of maliciousness.")
    elif http_code is not None and http_code >= 500:
        reasons.append(f"The server returned HTTP {http_code}; availability is degraded, but this is not treated as proof of maliciousness.")

    # Correlation rule: brand + suspicious auth context is a major security signal.
    if (domain_brand or typo) and keyword_points >= 3:
        add(8, "Brand/domain anomaly is combined with phishing-related URL language")

    score = max(0, min(100, round(score)))

    # Known external threat gets a hard floor.
    if gsb.get("safe") is False:
        score = max(85, score)

    status = risk_level(score)
    confidence = calculate_confidence(reach, page, gsb, evidence)

    if score == 0:
        reasons.insert(0, "No meaningful security-risk indicators were detected.")
    elif not any("risk" in r.lower() or "threat" in r.lower() or "impersonation" in r.lower() for r in reasons):
        reasons.insert(0, "Risk score is based on URL, domain, page-access and reputation evidence.")

    if not reach.get("reachable") and reach.get("dns") == "Resolved":
        confidence = min(confidence, 65)

    # Internal-only field; do not send raw HTML to the browser/API.
    page.pop("_raw_html", None)

    result = {
        "status": status,
        "invalid_url": False,
        "score": score,
        "confidence": confidence,
        "reasons": reasons[:8],
        "checks": checks,
        "host": host,
        "scheme": p.scheme,
        "url": original,
        "domain_status": reach["dns"],
        "http_status": reach["http"],
        "reachable": reach["reachable"],
        "reach_detail": reach["detail"],
        "page": page,
        "content_analysis_label": content_analysis_label(page),
        "google_safe_browsing": gsb,
        "friendly_statuses": friendly_statuses({
            "domain_status": reach["dns"],
            "http_status": reach["http"],
            "reachable": reach["reachable"],
            "page": page
        })
    }
    return result


def save(result):
    c = conn()
    try:
        c.execute(
            "INSERT INTO scans(url,status,score,confidence,domain_status,scanned_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                result.get("url", ""),
                result.get("status", ""),
                result.get("score", 0),
                result.get("confidence", 0),
                result.get("domain_status", ""),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        c.commit()
    finally:
        c.close()


def history():
    c = conn()
    try:
        rows = c.execute(
            "SELECT id,url,status,score,confidence,domain_status,scanned_at "
            "FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        c.close()


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    app.logger.exception("Unhandled SafeLink error")
    if request.path.startswith("/api/"):
        return jsonify({
            "error": "SafeLink could not complete this request. Check application logs."
        }), 500
    return render_template(
        "error.html",
        message="SafeLink could not complete this request. Please try again."
    ), 500


@app.route("/", methods=["GET", "POST"])
def index():
    result = analyze_url(request.form.get("url", "")) if request.method == "POST" else None
    if result and not result.get("invalid_url", False):
        save(result)
    return render_template("index.html", result=result, history=history()[:10])


@app.get("/history")
def hist():
    return render_template("history.html", history=history())


@app.post("/api/v1/scans")
def api_scan():
    result = analyze_url((request.get_json(silent=True) or {}).get("url", ""))
    if not result.get("invalid_url", False):
        save(result)
    return jsonify(result)


@app.get("/api/v1/scans")
def api_history():
    return jsonify(history())


@app.get("/api/v1/health")
def health():
    return jsonify({"status": "ok", "project": "SafeLink", "reachability_check": True})


@app.get("/export/csv")
def export():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ID", "URL", "Status", "Risk", "Confidence", "Domain Status", "Time"])
    for row in history():
        writer.writerow([
            row["id"], row["url"], row["status"], row["score"],
            row["confidence"], row["domain_status"], row["scanned_at"]
        ])
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=safelink_history.csv"}
    )


init_db()

if __name__ == "__main__":
    app.run(debug=True)

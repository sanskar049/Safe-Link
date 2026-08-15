import sqlite3,re,ipaddress,math,csv,io,socket,html as htmlmod
from datetime import datetime
from urllib.parse import urlparse,unquote
from difflib import SequenceMatcher
from flask import Flask,render_template,request,jsonify,Response
import requests
import os

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

app=Flask(__name__); DB="safelink.db"
BRANDS=["google","facebook","instagram","microsoft","apple","amazon","paypal","paytm","phonepe","flipkart","netflix","whatsapp","linkedin","sbi","hdfcbank","icicibank","axisbank"]
WORDS={"login":3,"signin":3,"verify":3,"secure":2,"account":2,"update":3,"password":4,"bank":4,"wallet":3,"payment":3,"confirm":3,"recover":3,"bonus":2,"free":2,"gift":2,"claim":2,"urgent":3,"suspended":4}
TLDS={"xyz":3,"top":3,"click":3,"work":2,"zip":3,"tk":3,"ml":3,"ga":3,"cf":3,"gq":3}

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
    c=conn(); c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT,status TEXT,score INTEGER,confidence REAL,domain_status TEXT,scanned_at TEXT)"); c.commit(); c.close()
def entropy(s):
    if not s:return 0
    n=len(s); return -sum((s.count(x)/n)*math.log2(s.count(x)/n) for x in set(s))

def reachability(url,host):
    try:
        socket.getaddrinfo(host,None)
    except (socket.gaierror,OSError):
        return {"dns":"Not resolved","http":"Not checked","reachable":False,"detail":"Domain name could not be resolved."}
    try:
        r=requests.head(url,allow_redirects=True,timeout=5)
        return {"dns":"Resolved","http":str(r.status_code),"reachable":True,"detail":f"Server responded with HTTP {r.status_code}."}
    except requests.RequestException:
        try:
            r=requests.get(url,allow_redirects=True,timeout=5,stream=True)
            return {"dns":"Resolved","http":str(r.status_code),"reachable":True,"detail":f"Server responded with HTTP {r.status_code}."}
        except requests.RequestException:
            return {"dns":"Resolved","http":"No response","reachable":False,"detail":"Domain resolves, but the web server did not respond."}



def browser_page_analysis(url, headers=None):
    """Render a page in Chromium for JS-heavy/403 pages.
    Returns None when Playwright/Chromium is unavailable.
    """
    if sync_playwright is None:
        return None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox","--disable-dev-shm-usage"]
            )
            context = browser.new_context(
                user_agent=(headers or {}).get("User-Agent"),
                locale="en-IN",
                java_script_enabled=True,
                ignore_https_errors=True,
                viewport={"width":1365,"height":900}
            )
            page = context.new_page()
            response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            # Give client-side apps a short time to render.
            page.wait_for_timeout(1200)
            final_url=page.url
            title=page.title()[:160]
            visible=page.locator("body").inner_text(timeout=3000)[:300000]
            html=page.content()[:600000]
            status=response.status if response else None
            browser.close()
            return {
                "status_code": str(status) if status else "Rendered",
                "final_url": final_url,
                "title": title,
                "visible": visible,
                "html": html,
                "reachable": True,
                "blocked": False,
                "detail": "Page rendered in a browser for JavaScript/content analysis."
            }
    except Exception as exc:
        return {"error": str(exc)[:180], "reachable": False}

def page_analysis(url):
    """Analyze public HTML plus safe fallback metadata when a site blocks requests."""
    result={"reachable":False,"title":"","signals":[],"brand_impersonation":[],"categories":[],
            "forms":0,"payment_signals":0,"policy_signals":0,"discount_signals":0,
            "status_code":"Not checked","detail":"Page content was not checked.","blocked":False}
    p=urlparse(url)
    host=(p.hostname or "").lower()
    headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
             "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "Accept-Language":"en-IN,en;q=0.9"}

    # Domain-level fallback vocabulary. This is intentionally conservative.
    domain_text=(host+" "+p.path).lower()
    fallback_fantasy=[
        "dream11","my11circle","mplfantasy","vision11","fantasyakhada",
        "fantasycricket","fantasysports","myteam11","halaplay"
    ]
    gambling_terms=[
        "casino","casinos","betting","bet","sportsbook","sports-betting",
        "gambling","gamble","poker","slots","slot-machine","roulette",
        "blackjack","jackpot","lottery","wager","bookmaker","bookie",
        "bet365","betway","parimatch","1xbet","betfair","draftkings","fanduel",
        "stake","22bet","melbet","dafabet","10bet","888casino","williamhill"
    ]
    if any(x in domain_text for x in fallback_fantasy):
        result["categories"].append("Fantasy sports / paid contests")
        result["signals"].append("Domain matches a fantasy-sports/paid-contest pattern")
    if any(x in domain_text for x in gambling_terms):
        result["categories"].append("Gambling / betting")
        result["signals"].append("Domain contains a gambling/betting indicator")

    try:
        r=requests.get(url,headers=headers,allow_redirects=True,timeout=8,stream=True)
        result["status_code"]=str(r.status_code)
        result["reachable"]=r.status_code<500
        final_url=r.url
        final_host=(urlparse(final_url).hostname or "").lower()
        result["final_host"]=final_host
        ctype=(r.headers.get("Content-Type") or "").lower()

        # Read a limited amount to avoid downloading huge pages.
        raw=r.raw.read(400000,decode_content=True)
        page=raw.decode(r.encoding or "utf-8",errors="ignore")

        title=re.search(r"<title[^>]*>(.*?)</title>",page,re.I|re.S)
        result["title"]=re.sub(r"\s+"," ",htmlmod.unescape(title.group(1))).strip()[:160] if title else ""

        # If the site blocks us, still use title/headers/final URL as metadata.
        if r.status_code in (401,403,429):
            result["blocked"]=True
            result["detail"]="Website blocked automated access (HTTP %s); fallback signals used." % r.status_code

        visible=re.sub(r"<script[^>]*>.*?</script>|<style[^>]*>.*?</style>"," ",page,flags=re.I|re.S)
        visible=re.sub(r"<[^>]+>"," ",visible)
        visible=re.sub(r"\s+"," ",htmlmod.unescape(visible)).lower()
        metadata=(visible+" "+result["title"].lower()+" "+host+" "+final_host).lower()

        def count(pattern): return len(re.findall(pattern,metadata,re.I))

        gc=count(r"\b(casino|casinos|gambling|gamble|betting|sportsbook|sports[- ]?betting|slots?|jackpot|roulette|blackjack|poker|lottery|bet now|wager|bookmaker|bookie|odds|live odds|bet slip)\b")
        fc=count(r"\b(fantasy sports?|fantasy cricket|fantasy football|fantasy league|paid contest|cash contest|real money|win cash|entry fee|prize pool|join contest|play and win|play & win|dream team|team creation)\b")
        sc=count(r"\b(add to cart|buy now|shop now|checkout|cart|order now|shipping|delivery|refund|return policy|track order)\b")
        pc=count(r"\b(upi|payment|pay now|credit card|debit card|bank transfer|net banking|wallet|razorpay|stripe|cash on delivery|cod|entry fee|deposit|withdrawal)\b")
        dc=count(r"\b(\d{2,3}\s*%\s*(off|discount)|flash sale|mega sale|limited time|lowest price|huge discount|clearance sale)\b")

        result["forms"]=len(re.findall(r"<form\b",page,re.I))
        result["payment_signals"]=pc
        result["discount_signals"]=dc
        result["policy_signals"]=count(r"\b(privacy policy|terms and conditions|terms of service|refund policy|return policy|contact us|about us)\b")

        if gc>=1 and "Gambling / betting" not in result["categories"]:
            result["categories"].append("Gambling / betting")
            result["signals"].append("Gambling or betting-related content detected")
        elif gc>=1:
            result["signals"].append("Gambling/betting content confirmed by page metadata")
        if fc>=2 and "Fantasy sports / paid contests" not in result["categories"]:
            result["categories"].append("Fantasy sports / paid contests")
            result["signals"].append("Fantasy sports or paid-contest content detected")
        if sc>=2 and "E-commerce" not in result["categories"]:
            result["categories"].append("E-commerce")
            result["signals"].append("E-commerce/shopping content detected")
        if pc>=2: result["signals"].append("Payment-related content detected")
        if dc: result["signals"].append("Discount/sale language detected")

        # Brand impersonation: do NOT flag a brand merely because its name appears
        # in a footer, social-media link, review, article, or external link.
        # Require stronger evidence such as brand + login/account/payment language,
        # a brand-like title, or a suspicious host containing the brand name.
        official_domains={
            "amazon":{"amazon.com","amazon.in","www.amazon.com","www.amazon.in"},
            "flipkart":{"flipkart.com","www.flipkart.com"},
            "facebook":{"facebook.com","www.facebook.com"},
            "instagram":{"instagram.com","www.instagram.com"},
            "linkedin":{"linkedin.com","www.linkedin.com"},
            "google":{"google.com","www.google.com"},
            "microsoft":{"microsoft.com","www.microsoft.com"},
            "apple":{"apple.com","www.apple.com"},
            "paypal":{"paypal.com","www.paypal.com"},
            "netflix":{"netflix.com","www.netflix.com"},
            "youtube":{"youtube.com","www.youtube.com"},
        }
        brand_context_words=r"login|log in|sign in|signin|account|password|verify|verification|secure|payment|checkout|wallet|otp|one[- ]time password|bank|customer support"
        suspicious_host_words=r"login|verify|secure|account|support|update|bonus|offer|claim|wallet|auth"
        for b in BRANDS:
            brand=re.escape(b)
            official=official_domains.get(b,{b+".com","www."+b+".com"})
            if final_host in official or host in official:
                continue

            # A suspicious host that itself embeds the brand is strong evidence.
            host_has_brand=bool(re.search(r"(^|[.\-_])"+brand+r"([.\-_]|$)",host,re.I))
            host_has_suspicious=bool(re.search(suspicious_host_words,host,re.I))

            # Look at visible text/title only, not raw HTML links.
            brand_context=bool(re.search(
                r"\b"+brand+r"\b.{0,80}(?:"+brand_context_words+r")|"+
                r"(?:"+brand_context_words+r").{0,80}\b"+brand+r"\b",
                visible,re.I
            ))
            title_brand=bool(re.search(r"\b"+brand+r"\b",result["title"],re.I))
            title_context=bool(re.search(brand_context_words,result["title"],re.I))

            # Strong impersonation evidence requires at least two signals,
            # except a brand embedded in a suspicious-looking host.
            strong=(host_has_brand and host_has_suspicious) or                    (brand_context and (title_brand or host_has_brand)) or                    (title_brand and title_context and host_has_suspicious)

            if strong and b not in result["brand_impersonation"]:
                result["brand_impersonation"].append(b)

        if result["brand_impersonation"]:
            result["signals"].append(
                "Possible brand impersonation based on domain/page-context signals: "+
                ", ".join(result["brand_impersonation"][:4])
            )

        if "E-commerce" in result["categories"]:
            if pc>=2 and dc>=1: result["signals"].append("Shopping + payment + strong discount combination")
            if result["policy_signals"]<2: result["signals"].append("Few standard policy/contact pages detected")
            if result["forms"]>0: result["signals"].append("Order/input form detected")
        if "Fantasy sports / paid contests" in result["categories"] and pc>=1:
            result["signals"].append("Fantasy/contest content with payment or entry-fee signals")

        return result
    except requests.RequestException:
        # Second layer: render the page with Chromium for JS-heavy sites and
        # servers that reject simple HTTP clients.
        rendered=browser_page_analysis(url,headers)
        if rendered and rendered.get("reachable"):
            result["status_code"]=rendered.get("status_code","Rendered")
            result["reachable"]=True
            result["blocked"]=False
            result["detail"]=rendered.get("detail","Browser-rendered fallback used.")
            result["final_host"]=(urlparse(rendered.get("final_url",url)).hostname or "").lower()
            result["title"]=rendered.get("title","")[:160]
            page=rendered.get("html","")
            visible=re.sub(r"<script[^>]*>.*?</script>|<style[^>]*>.*?</style>"," ",page,flags=re.I|re.S)
            # Prefer actual browser-visible text when available.
            visible_text=rendered.get("visible","")
            visible=(visible_text+" "+visible)
            visible=re.sub(r"<[^>]+>"," ",visible)
            visible=re.sub(r"\s+"," ",htmlmod.unescape(visible)).lower()
            metadata=(visible+" "+result["title"].lower()+" "+host).lower()

            def count(pattern): return len(re.findall(pattern,metadata,re.I))
            gc=count(r"\b(casino|casinos|gambling|gamble|betting|sportsbook|sports[- ]?betting|slots?|jackpot|roulette|blackjack|poker|lottery|bet now|wager|bookmaker|bookie|odds|live odds|bet slip)\b")
            fc=count(r"\b(fantasy sports?|fantasy cricket|fantasy football|fantasy league|paid contest|cash contest|real money|win cash|entry fee|prize pool|join contest|play and win|play & win|dream team|team creation)\b")
            sc=count(r"\b(add to cart|buy now|shop now|checkout|cart|order now|shipping|delivery|refund|return policy|track order)\b")
            pc=count(r"\b(upi|payment|pay now|credit card|debit card|bank transfer|net banking|wallet|razorpay|stripe|cash on delivery|cod|entry fee|deposit|withdrawal)\b")
            dc=count(r"\b(\d{2,3}\s*%\s*(off|discount)|flash sale|mega sale|limited time|lowest price|huge discount|clearance sale)\b")
            result["forms"]=len(re.findall(r"<form\b",page,re.I))
            result["payment_signals"]=pc; result["discount_signals"]=dc
            result["policy_signals"]=count(r"\b(privacy policy|terms and conditions|terms of service|refund policy|return policy|contact us|about us)\b")
            if gc and "Gambling / betting" not in result["categories"]:
                result["categories"].append("Gambling / betting"); result["signals"].append("Gambling/betting content detected in rendered page")
            if fc>=2 and "Fantasy sports / paid contests" not in result["categories"]:
                result["categories"].append("Fantasy sports / paid contests"); result["signals"].append("Fantasy/paid-contest content detected in rendered page")
            if sc>=2 and "E-commerce" not in result["categories"]:
                result["categories"].append("E-commerce"); result["signals"].append("Shopping/e-commerce content detected in rendered page")
            if count(r"\b(movie|movies|series|web series|watch online|watch free|download movie|download movies|1080p|720p|480p|camrip|webrip|bluray|dual audio|subtitles|torrent|magnet|pirated|piracy|free streaming)\b")>=2:
                if "Potentially unauthorized streaming / piracy" not in result["categories"]:
                    result["categories"].append("Potentially unauthorized streaming / piracy")
                    result["signals"].append("Multiple signals associated with unauthorized movie/TV streaming detected")
            if pc>=2: result["signals"].append("Payment-related content detected")
            if dc: result["signals"].append("Discount/sale language detected")
            return result

        result["blocked"]=True
        result["detail"]="Website blocked both direct and browser-based access; URL/domain and reputation signals were used."
        if result["categories"]:
            result["signals"].append("Page unavailable; category inferred from available URL/domain signals")
        return result


def google_safe_browsing_check(url):
    """Google Safe Browsing API v5 URL reputation check."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    result = {"enabled": bool(api_key), "status": "Not configured" if not api_key else "Checking",
              "safe": None, "threats": [], "error": None}
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
        result["threats"] = [{"url": x.get("url", ""), "types": x.get("threatTypes", [])} for x in threats]
        result["safe"] = not bool(threats)
        result["status"] = "Threat detected" if threats else "No known Google threat"
    except requests.RequestException as exc:
        result["status"] = "API unavailable"
        result["error"] = str(exc)[:160]
    except ValueError:
        result["status"] = "Invalid API response"
        result["error"] = "Google returned a non-JSON response"
    return result

def analyze_url(url):
    original=url.strip()
    if not original:return {"status":"Invalid","score":100,"confidence":100,"reasons":["No URL entered."],"checks":[],"url":url}
    normalized=original if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://",original) else "http://"+original
    try:p=urlparse(normalized); host=(p.hostname or "").lower()
    except:return {"status":"Invalid","score":100,"confidence":100,"reasons":["Invalid URL."],"checks":[],"url":url}
    if not host:return {"status":"Invalid","score":100,"confidence":100,"reasons":["Invalid URL."],"checks":[],"url":url}
    try:is_ip=bool(ipaddress.ip_address(host))
    except ValueError:is_ip=False
    parts=host.split("."); tld=parts[-1] if len(parts)>1 else ""; clean=host.replace("www.","").split(".")[0]
    brand=[b for b in BRANDS if b in host and host not in {b+".com","www."+b+".com"}]
    typo=[b for b in BRANDS if .72<=SequenceMatcher(None,clean,b).ratio()<1 and abs(len(clean)-len(b))<=2]
    text=unquote(original.lower()); score=0; reasons=[]; checks=[]
    def add(n,r):
        nonlocal score; score+=n; reasons.append(r)

    if is_ip: reach={"dns":"IP","http":"Not checked","reachable":False,"detail":"IP host; DNS check not applicable."}
    else: reach=reachability(normalized,host)
    if not is_ip and reach["dns"]=="Not resolved":
        add(35,"Domain could not be resolved (it may not exist or its DNS may be unavailable)")
    elif not is_ip and not reach["reachable"]:
        add(8,"Domain resolves but the web server did not respond")
    checks.append(("Domain / DNS","danger" if reach["dns"]=="Not resolved" else ("warn" if not reach["reachable"] and not is_ip else "pass"),reach["dns"]))

    if p.scheme=="https": checks.append(("HTTPS","pass","Enabled"))
    else: add(8,"Website does not use HTTPS"); checks.append(("HTTPS","warn","HTTP connection"))
    if is_ip:add(24,"Raw IP address used instead of a domain")
    checks.append(("IP address","danger" if is_ip else "pass","Raw IP" if is_ip else "Normal domain"))

    L=len(original)
    if L>120:add(10,"Very long URL")
    elif L>80:add(5,"Long URL")
    checks.append(("URL length","warn" if L>80 else "pass",f"{L} characters"))

    if "@" in original:add(18,"@ symbol can hide the real destination")
    if original.count("//")>1:add(8,"Extra // sequence suggests obfuscation")
    if "%" in original:add(5,"Percent-encoded characters present")
    checks.append(("Obfuscation","danger" if "@" in original or original.count("//")>1 else ("warn" if "%" in original else "pass"),"Suspicious pattern" if "@" in original or original.count("//")>1 or "%" in original else "None"))

    puny="xn--" in host
    if puny:add(18,"Punycode/look-alike hostname detected")
    checks.append(("Look-alike","danger" if puny else "pass","Punycode" if puny else "None"))

    subs=max(0,len(parts)-2)
    if subs>=4:add(12,"Unusually many subdomains")
    elif subs==3:add(4,"Several subdomains")
    checks.append(("Subdomains","warn" if subs>=3 else "pass",str(subs)))

    hy=host.count("-")
    if hy>=3:add(9,"Several hyphens in hostname")
    elif hy>=2:add(4,"Multiple hyphens")
    checks.append(("Domain structure","warn" if hy>=2 else "pass",f"{hy} hyphens"))

    if tld in TLDS:add(TLDS[tld],f"Potentially abused TLD: .{tld}")
    checks.append(("TLD","warn" if tld in TLDS else "pass","."+tld if tld else "Unknown"))

    kw=sum(v for k,v in WORDS.items() if k in text)
    if kw:add(min(18,kw),"Phishing-related keywords detected")
    checks.append(("Keywords","warn" if kw else "pass",f"{kw} weighted points"))

    if brand:add(min(18,6*len(brand)),"Possible brand impersonation: "+", ".join(brand[:3]))
    if typo:add(min(16,8*len(typo)),"Possible typosquatting: "+", ".join(typo[:3]))
    checks.append(("Brand / typosquatting","danger" if brand or typo else "pass",", ".join((brand+typo)[:3]) if brand or typo else "No obvious match"))

    digits=sum(x.isdigit() for x in host)
    if digits>=5 and digits/max(1,len(host))>.25:add(6,"Unusually high digit ratio")
    checks.append(("Hostname complexity","warn" if digits>=5 else "pass",f"{digits} digits"))

    params=(p.query or "").count("="); path=len(p.path or "")
    if params>=6:add(5,"Many query parameters")
    if path>120:add(5,"Very long URL path")
    checks.append(("Path / query","warn" if params>=6 or path>120 else "pass",f"{params} parameters"))

    ent=entropy(host)
    if ent>4.2 and len(host)>18:add(5,"High hostname randomness")
    checks.append(("Hostname randomness","warn" if ent>4.2 and len(host)>18 else "pass",f"{ent:.2f} entropy"))

    page={"reachable":False,"signals":[],"brand_impersonation":[],"categories":[],"forms":0,"payment_signals":0,"policy_signals":0,"discount_signals":0,"status_code":"Not checked","title":"","detail":"Page content was not checked."}
    gsb = google_safe_browsing_check(normalized)
    if gsb.get("safe") is False:
        threat_types=[]
        for item in gsb.get("threats",[]):
            threat_types.extend(item.get("types",[]))
        threat_types=list(dict.fromkeys(threat_types))
        add(45, "Google Safe Browsing: known threat detected" +
            (f" ({', '.join(threat_types)})" if threat_types else ""))
    checks.append(("Google Safe Browsing",
                   "danger" if gsb.get("safe") is False else ("pass" if gsb.get("enabled") else "warn"),
                   ("Threat detected" if gsb.get("safe") is False else
                    ("No known threat" if gsb.get("enabled") else "Not configured"))))

    if reach["dns"]!="Not resolved" and not is_ip:
        page=page_analysis(normalized)
        if page["categories"]:
            # Categories are informational. Add only a small risk contribution.
            category_weight = 2 if "Gambling / betting" in page["categories"] else 0
            add(category_weight,"Website category: "+", ".join(page["categories"]))
        if page["brand_impersonation"]: add(min(24,8*len(page["brand_impersonation"])),"Page may impersonate: "+", ".join(page["brand_impersonation"][:3]))
        if page["payment_signals"]>=2 and page["discount_signals"]>=1 and "E-commerce" in page["categories"]: add(10,"E-commerce + payment + aggressive discount signals")
        if page["policy_signals"]<2 and "E-commerce" in page["categories"]: add(5,"E-commerce page has limited standard policy/contact signals")
        checks.append(("Website content","danger" if page["brand_impersonation"] else ("warn" if page["signals"] else "pass")," / ".join(page["signals"][:2]) if page["signals"] else "No major content warning"))
    else:
        checks.append(("Website content","warn" if reach["dns"]!="Not resolved" else "danger","Not checked" if reach["dns"]=="Not resolved" else "Skipped"))
    score=min(100,round(score))
    if reach["dns"]=="Not resolved": status="Unreachable / Invalid Domain" if score<60 else ("Suspicious" if score<80 else "Dangerous")
    else: status="Dangerous" if score>=60 else ("Suspicious" if score>=30 else "No Suspicious Patterns")
    confidence=min(99,round(70+abs(score-30)*.45,1))
    if gsb.get("safe") is False:
        score=min(100,max(80,score))
        status="Dangerous"
        confidence=99
    return {"status":status,"score":score,"confidence":confidence,"reasons":reasons or ["No major suspicious URL or website-content patterns detected."],"checks":checks,"host":host,"scheme":p.scheme,"url":original,"domain_status":reach["dns"],"http_status":reach["http"],"reachable":reach["reachable"],"reach_detail":reach["detail"],"page":page,"google_safe_browsing":gsb,"friendly_statuses":friendly_statuses({"domain_status":reach["dns"],"http_status":reach["http"],"reachable":reach["reachable"],"page":page})}


def friendly_statuses(result):
    dns=result.get("domain_status",""); http=result.get("http_status",""); reachable=result.get("reachable",False)
    page=result.get("page",{}) or {}; ps=page.get("status_code","")
    domain=("Not found","danger","We could not find this website's domain address.") if dns=="Not resolved" else (
        ("IP address used","warn","The URL uses a numeric server address instead of a normal domain name.") if dns=="IP" else
        ("Found","pass","The website's domain address was successfully located."))
    try: hs=int(str(http).split()[0]) if str(http).split()[0].isdigit() else None
    except: hs=None
    if hs==403: server=("Access restricted","warn","The website's server did not allow our scanner to access the page. This does not by itself mean the website is unsafe.")
    elif hs==404: server=("Page not found","warn","The server responded, but the requested page could not be found.")
    elif hs is not None and 200<=hs<300: server=("Responded","pass","The website's server accepted the request and returned a response.")
    elif hs is not None and 300<=hs<400: server=("Redirected","warn","The website sent the request to another address.")
    elif hs is not None and hs>=500: server=("Server problem","danger","The website's server reported an internal/server-side problem.")
    elif reachable: server=("Responded","pass","The website's server responded to our request.")
    else: server=("No response","warn","The website's server did not respond to our request.")
    try: psc=int(str(ps).split()[0]) if str(ps).split()[0].isdigit() else None
    except: psc=None
    if page.get("blocked") or psc==403: pageui=("Access restricted","warn","The webpage could not be fully opened by our scanner. Other checks can still be used.")
    elif psc==404: pageui=("Page not found","warn","The requested webpage was not found.")
    elif psc is not None and 200<=psc<300: pageui=("Loaded","pass","The webpage was successfully accessed for analysis.")
    elif psc is not None and 300<=psc<400: pageui=("Redirected","warn","The webpage redirected to another address.")
    elif psc is not None and psc>=500: pageui=("Unavailable","danger","The webpage could not be loaded because the server reported an error.")
    elif page.get("reachable"): pageui=("Available","pass","The webpage responded and could be checked.")
    else: pageui=("Not checked","warn","The webpage could not be fully checked.")
    return {"domain":{"label":domain[0],"state":domain[1],"help":domain[2],"technical":dns},
            "server":{"label":server[0],"state":server[1],"help":server[2],"technical":http},
            "page":{"label":pageui[0],"state":pageui[1],"help":pageui[2],"technical":ps}}

def save(r):
    c=conn();c.execute("INSERT INTO scans(url,status,score,confidence,domain_status,scanned_at) VALUES(?,?,?,?,?,?)",(r["url"],r["status"],r["score"],r["confidence"],r["domain_status"],datetime.now().strftime("%Y-%m-%d %H:%M:%S")));c.commit();c.close()
def history():
    c=conn();rows=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall();c.close();return[dict(x) for x in rows]

@app.route("/",methods=["GET","POST"])
def index():
    r=analyze_url(request.form.get("url","")) if request.method=="POST" else None
    if r and r["status"]!="Invalid":save(r)
    return render_template("index.html",result=r,history=history()[:10])
@app.get("/history")
def hist():return render_template("history.html",history=history())
@app.post("/api/v1/scans")
def api_scan():
    r=analyze_url((request.get_json(silent=True) or {}).get("url",""))
    if r["status"]!="Invalid":save(r)
    return jsonify(r)
@app.get("/api/v1/scans")
def api_history():return jsonify(history())
@app.get("/api/v1/health")
def health():return jsonify({"status":"ok","project":"SafeLink","reachability_check":True})
@app.get("/export/csv")
def export():
    out=io.StringIO();w=csv.writer(out);w.writerow(["ID","URL","Status","Risk","Confidence","Domain Status","Time"])
    for r in history():w.writerow([r["id"],r["url"],r["status"],r["score"],r["confidence"],r["domain_status"],r["scanned_at"]])
    return Response(out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=safelink_history.csv"})
init_db()
if __name__=="__main__":app.run(debug=True)

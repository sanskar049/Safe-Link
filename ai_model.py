from __future__ import annotations

import json
import math
import os
import re
from urllib.parse import unquote, urlparse

import joblib

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model_compressed.joblib")
HOSTS_PATH = os.path.join(BASE_DIR, "models", "learned_legitimate_hosts.json")

MODEL_FEATURES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "slash_count", "digit_count",
    "special_count", "percent_count", "at_count", "ampersand_count",
    "equals_count", "question_count", "subdomain_count", "has_https",
    "has_ip", "has_punycode", "suspicious_keyword_count",
    "encoded_character_count", "double_slash_count",
    "hostname_entropy", "path_entropy", "host_digit_ratio",
    "url_digit_ratio",
]

SUSPICIOUS_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "password", "account", "secure", "update", "confirm",
    "bank", "payment", "wallet", "otp", "authenticate",
    "suspended", "urgent", "recover",
]

# Exact-host checks are a separate evidence layer.
# They do not replace the ML model and only apply to an exact hostname.
TRUSTED_EXACT_HOSTS = {
    "google.com", "www.google.com", "google.co.in",
    "flipkart.com", "www.flipkart.com",
    "amazon.in", "www.amazon.in", "amazon.com", "www.amazon.com",
    "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
    "github.com", "www.github.com", "wikipedia.org", "www.wikipedia.org",
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com", "youtube.com", "www.youtube.com",
    "netflix.com", "www.netflix.com", "paypal.com", "www.paypal.com",
    "openai.com", "www.openai.com", "chatgpt.com",
    "adobe.com", "www.adobe.com", "spotify.com", "open.spotify.com",
    "reddit.com", "www.reddit.com", "stackoverflow.com", "www.stackoverflow.com",
    "cloudflare.com", "www.cloudflare.com", "zoom.us", "www.zoom.us",
    "notion.so", "www.notion.so", "x.com", "www.x.com",
    "irctc.co.in", "www.irctc.co.in", "uidai.gov.in", "www.uidai.gov.in",
    "india.gov.in", "www.india.gov.in", "mygov.in", "www.mygov.in",
    "sbi.co.in", "www.sbi.co.in", "hdfcbank.com", "www.hdfcbank.com",
    "icicibank.com", "www.icicibank.com", "axisbank.com", "www.axisbank.com",
    "pnbindia.in", "www.pnbindia.in", "canarabank.com", "www.canarabank.com",
}

_model = None
_learned_hosts = None


def entropy(text):
    if not text:
        return 0.0
    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def parse_url(url):
    url = str(url).strip()
    normalized = (
        url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
        else "http://" + url
    )
    try:
        parsed = urlparse(normalized)
        return normalized, parsed.hostname or "", parsed.path or "", parsed.query or ""
    except (ValueError, IndexError):
        return normalized, "", normalized, ""


def extract_features(url):
    url = str(url).strip()
    normalized, hostname, path, query = parse_url(url)

    f = {}
    f["url_length"] = len(url)
    f["hostname_length"] = len(hostname)
    f["path_length"] = len(path)
    f["query_length"] = len(query)

    f["dot_count"] = url.count(".")
    f["hyphen_count"] = url.count("-")
    f["slash_count"] = url.count("/")
    f["digit_count"] = sum(c.isdigit() for c in url)
    f["special_count"] = sum(not c.isalnum() for c in url)
    f["percent_count"] = url.count("%")
    f["at_count"] = url.count("@")
    f["ampersand_count"] = url.count("&")
    f["equals_count"] = url.count("=")
    f["question_count"] = url.count("?")

    parts = [x for x in hostname.split(".") if x]
    f["subdomain_count"] = max(0, len(parts) - 2)
    f["has_https"] = int(normalized.lower().startswith("https://"))
    f["has_ip"] = int(bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname)))
    f["has_punycode"] = int("xn--" in hostname.lower())

    try:
        decoded_url = unquote(url).lower()
    except Exception:
        decoded_url = url.lower()

    f["suspicious_keyword_count"] = sum(
        1 for word in SUSPICIOUS_WORDS if word in decoded_url
    )
    f["encoded_character_count"] = url.count("%")
    f["double_slash_count"] = url.count("//")
    f["hostname_entropy"] = entropy(hostname)
    f["path_entropy"] = entropy(path)
    f["host_digit_ratio"] = sum(c.isdigit() for c in hostname) / max(1, len(hostname))
    f["url_digit_ratio"] = sum(c.isdigit() for c in url) / max(1, len(url))
    return f


def load_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"AI model not found: {MODEL_PATH}")
        _model = joblib.load(MODEL_PATH)
    return _model


def load_learned_hosts():
    global _learned_hosts
    if _learned_hosts is None:
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                _learned_hosts = json.load(f)
        except Exception:
            _learned_hosts = {}
    return _learned_hosts


def predict_url(url):
    model = load_model()
    features = extract_features(url)
    vector = [[features[name] for name in MODEL_FEATURES]]

    raw_prediction = str(model.predict(vector)[0])
    probabilities = {}

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vector)[0]
        probabilities = {
            str(label): round(float(prob) * 100, 2)
            for label, prob in zip(model.classes_, probs)
        }

    raw_confidence = max(probabilities.values()) if probabilities else None
    raw_ai_risk = (
        probabilities.get("Suspicious", 0.0) * 0.50
        + probabilities.get("Phishing", 0.0)
    )

    # Exact-host evidence layer.
    # This fixes the known limitation of the 25 structural URL features:
    # they cannot reliably distinguish "www.google.com" from a phishing
    # hostname that merely contains the word "google".
    _, hostname, _, _ = parse_url(url)
    hostname = hostname.lower().rstrip(".")

    learned_hosts = load_learned_hosts()
    learned_is_legit = hostname in learned_hosts
    trusted = hostname in TRUSTED_EXACT_HOSTS

    postprocessed = False
    reason = None

    if trusted or learned_is_legit:
        prediction = "Legitimate"
        # These are system-level postprocessed values, not raw ML probabilities.
        confidence = max(float(raw_confidence or 0), 99.0)
        ai_risk = min(float(raw_ai_risk), 2.0)
        postprocessed = True
        reason = "Exact hostname matched a trusted/learned legitimate-domain evidence rule."
    else:
        prediction = raw_prediction
        confidence = raw_confidence
        ai_risk = raw_ai_risk

    return {
        "enabled": True,
        "prediction": prediction,
        "confidence": round(confidence, 2) if confidence is not None else None,
        "ai_risk": round(ai_risk, 2),
        "probabilities": probabilities,
        "raw_prediction": raw_prediction,
        "raw_confidence": round(raw_confidence, 2) if raw_confidence is not None else None,
        "raw_ai_risk": round(raw_ai_risk, 2),
        "postprocessed": postprocessed,
        "postprocess_reason": reason,
        "hostname_evidence": {
            "hostname": hostname,
            "trusted_exact_host": trusted,
            "learned_legitimate_host": learned_is_legit,
        },
    }

from __future__ import annotations

import math
import os
import re
from urllib.parse import unquote, urlparse

import joblib

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "phishing_model_compressed.joblib",
)

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

_model = None


def entropy(text):
    if not text:
        return 0.0
    return -sum(
        (text.count(ch) / len(text))
        * math.log2(text.count(ch) / len(text))
        for ch in set(text)
        if text.count(ch)
    )


def extract_features(url):
    url = str(url).strip()
    normalized = (
        url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
        else "http://" + url
    )

    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except (ValueError, IndexError):
        hostname, path, query = "", normalized, ""

    f = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "slash_count": url.count("/"),
        "digit_count": sum(c.isdigit() for c in url),
        "special_count": sum(not c.isalnum() for c in url),
        "percent_count": url.count("%"),
        "at_count": url.count("@"),
        "ampersand_count": url.count("&"),
        "equals_count": url.count("="),
        "question_count": url.count("?"),
    }

    parts = [x for x in hostname.split(".") if x]
    f["subdomain_count"] = max(0, len(parts) - 2)
    f["has_https"] = int(normalized.lower().startswith("https://"))
    f["has_ip"] = int(bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname)))
    f["has_punycode"] = int("xn--" in hostname.lower())

    try:
        decoded = unquote(url).lower()
    except Exception:
        decoded = url.lower()

    f["suspicious_keyword_count"] = sum(
        1 for word in SUSPICIOUS_WORDS if word in decoded
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


def predict_url(url):
    model = load_model()
    features = extract_features(url)
    vector = [[features[name] for name in MODEL_FEATURES]]

    prediction = str(model.predict(vector)[0])
    probabilities = {}

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vector)[0]
        probabilities = {
            str(label): round(float(prob) * 100, 2)
            for label, prob in zip(model.classes_, probs)
        }

    confidence = max(probabilities.values()) if probabilities else None

    # AI-only risk: Legitimate=0, Suspicious=50, Phishing=100.
    ai_risk = (
        probabilities.get("Suspicious", 0.0) * 0.50
        + probabilities.get("Phishing", 0.0)
    )

    return {
        "enabled": True,
        "prediction": prediction,
        "confidence": round(confidence, 2) if confidence is not None else None,
        "ai_risk": round(ai_risk, 2),
        "probabilities": probabilities,
    }

import math, os, re, joblib, pandas as pd
from urllib.parse import urlparse, unquote
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

DATASET = "malicious_phish.csv"
MODEL_OUT = "models/phishing_model_compressed.joblib"

SUSPICIOUS_WORDS = [
    "login","signin","sign-in","verify","verification","password","account",
    "secure","update","confirm","bank","payment","wallet","otp","authenticate",
    "suspended","urgent","recover"
]

def entropy(text):
    if not text: return 0
    probabilities = [text.count(c)/len(text) for c in set(text)]
    return -sum(p*math.log2(p) for p in probabilities if p > 0)

def extract_features(url):
    url = str(url).strip()
    normalized = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except (ValueError, IndexError):
        hostname, path, query = "", normalized, ""

    parts = [x for x in hostname.split(".") if x]
    decoded_url = unquote(url).lower()

    return {
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
        "subdomain_count": max(0, len(parts)-2),
        "has_https": int(normalized.lower().startswith("https://")),
        "has_ip": int(bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))),
        "has_punycode": int("xn--" in hostname.lower()),
        "suspicious_keyword_count": sum(1 for w in SUSPICIOUS_WORDS if w in decoded_url),
        "encoded_character_count": url.count("%"),
        "double_slash_count": url.count("//"),
        "hostname_entropy": entropy(hostname),
        "path_entropy": entropy(path),
        "host_digit_ratio": sum(c.isdigit() for c in hostname)/max(1,len(hostname)),
        "url_digit_ratio": sum(c.isdigit() for c in url)/max(1,len(url)),
    }

def main():
    df = pd.read_csv(DATASET)
    df["class"] = df["type"].map({
        "benign":"Legitimate",
        "phishing":"Phishing",
        "defacement":"Suspicious",
        "malware":"Suspicious"
    })
    df = df.dropna(subset=["class"])

    n = 90000
    balanced = pd.concat([
        df[df["class"]=="Legitimate"].sample(n=n, random_state=42),
        df[df["class"]=="Suspicious"].sample(n=n, random_state=42),
        df[df["class"]=="Phishing"].sample(n=n, random_state=42),
    ], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    X = pd.DataFrame(balanced["url"].map(extract_features).tolist())
    y = balanced["class"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=.20, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, pred))
    print(classification_report(y_test, pred, digits=4))
    print(confusion_matrix(y_test, pred, labels=["Legitimate","Phishing","Suspicious"]))

    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump(model, MODEL_OUT, compress=3)
    print("Saved:", MODEL_OUT)

if __name__ == "__main__":
    main()

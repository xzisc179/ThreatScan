from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import math
import urllib.parse
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ─── BLACKLIST ────────────────────────────────────────────────────────────────
BLACKLISTED_DOMAINS = {
    "phishing-example.com", "malware-site.net", "evil-login.com",
    "secure-paypal-login.tk", "bank-verify.ml", "account-suspended.ga",
    "free-bitcoin-now.cf", "download-virus.ru", "hacked-site.pw",
    "credential-harvest.xyz", "fake-amazon.tk", "login-google-verify.ml",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "paypal", "ebay", "amazon", "google", "microsoft", "apple",
    "password", "credential", "free", "winner", "prize", "click", "urgent",
    "suspended", "limited", "wallet", "crypto", "bitcoin", "invoice",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".xyz", ".top",
    ".click", ".download", ".review", ".country", ".kim", ".science",
    ".work", ".party", ".loan", ".win", ".racing",
}

# ─── FEATURE EXTRACTION ───────────────────────────────────────────────────────
def extract_features(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        full = url.lower()

        # Length features
        url_length = len(url)
        domain_length = len(domain)

        # Special char counts
        dot_count = url.count(".")
        hyphen_count = url.count("-")
        at_count = url.count("@")
        slash_count = url.count("/")
        question_count = url.count("?")
        eq_count = url.count("=")
        amp_count = url.count("&")

        # IP address as domain
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))

        # HTTPS
        has_https = parsed.scheme == "https"

        # Subdomain depth
        subdomain_count = len(domain.split(".")) - 2

        # Suspicious keywords in URL
        keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)

        # Entropy of domain (high entropy = random-looking = suspicious)
        def shannon_entropy(s):
            if not s:
                return 0
            freq = {c: s.count(c) / len(s) for c in set(s)}
            return -sum(p * math.log2(p) for p in freq.values())

        domain_entropy = shannon_entropy(re.sub(r"\.[^.]+$", "", domain))

        # TLD check
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        suspicious_tld = tld in SUSPICIOUS_TLDS

        # Digit ratio in domain
        base_domain = domain.split(".")[0]
        digit_ratio = sum(c.isdigit() for c in base_domain) / max(len(base_domain), 1)

        # Redirect patterns
        has_redirect = "redirect" in full or "url=" in full or "link=" in full

        # Encoded characters
        has_encoding = "%" in url

        return {
            "url_length": url_length,
            "domain_length": domain_length,
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "at_count": at_count,
            "slash_count": slash_count,
            "question_count": question_count,
            "eq_count": eq_count,
            "amp_count": amp_count,
            "is_ip": int(is_ip),
            "has_https": int(has_https),
            "subdomain_count": max(subdomain_count, 0),
            "keyword_hits": keyword_hits,
            "domain_entropy": round(domain_entropy, 3),
            "suspicious_tld": int(suspicious_tld),
            "digit_ratio": round(digit_ratio, 3),
            "has_redirect": int(has_redirect),
            "has_encoding": int(has_encoding),
            "domain": domain,
            "tld": tld,
        }
    except Exception as e:
        return {}


# ─── RULE-BASED ML SCORER (no sklearn needed) ────────────────────────────────
def ml_score(features: dict) -> tuple[float, list]:
    """
    Heuristic scoring that mimics a decision-tree classifier.
    Returns (risk_score 0-1, reasons list).
    """
    score = 0.0
    reasons = []

    # Hard signals
    if features.get("is_ip"):
        score += 0.35
        reasons.append("IP address used instead of domain name")
    if features.get("at_count", 0) > 0:
        score += 0.25
        reasons.append("@ symbol found in URL (credential trick)")
    if not features.get("has_https"):
        score += 0.15
        reasons.append("No HTTPS — unencrypted connection")
    if features.get("suspicious_tld"):
        score += 0.20
        reasons.append(f"Suspicious TLD: {features.get('tld')}")
    if features.get("has_redirect"):
        score += 0.15
        reasons.append("URL contains redirect parameters")

    # Length-based
    url_len = features.get("url_length", 0)
    if url_len > 100:
        score += 0.15
        reasons.append(f"Unusually long URL ({url_len} chars)")
    elif url_len > 75:
        score += 0.08

    # Subdomain abuse
    sd = features.get("subdomain_count", 0)
    if sd >= 3:
        score += 0.20
        reasons.append(f"Excessive subdomains ({sd})")
    elif sd == 2:
        score += 0.10

    # Hyphens in domain
    if features.get("hyphen_count", 0) >= 3:
        score += 0.12
        reasons.append("Multiple hyphens — common in phishing domains")

    # Keyword hits
    kw = features.get("keyword_hits", 0)
    if kw >= 3:
        score += 0.20
        reasons.append(f"{kw} phishing-related keywords detected")
    elif kw >= 1:
        score += kw * 0.06

    # Entropy (random domains)
    entropy = features.get("domain_entropy", 0)
    if entropy > 3.8:
        score += 0.15
        reasons.append(f"High domain randomness (entropy {entropy:.2f})")
    elif entropy > 3.2:
        score += 0.07

    # Digit ratio
    if features.get("digit_ratio", 0) > 0.4:
        score += 0.10
        reasons.append("High digit ratio in domain")

    # Encoding
    if features.get("has_encoding"):
        score += 0.08
        reasons.append("URL-encoded characters detected")

    # Many query params
    if features.get("eq_count", 0) > 4:
        score += 0.08
        reasons.append("Many query parameters")

    return min(score, 1.0), reasons


# ─── MAIN ANALYSIS ────────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    url = url.strip()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower().replace("www.", "")

    # 1. Blacklist check
    blacklisted = domain in BLACKLISTED_DOMAINS
    if blacklisted:
        return {
            "url": url,
            "verdict": "MALICIOUS",
            "risk_score": 1.0,
            "confidence": "High",
            "method": "Blacklist",
            "reasons": [f"Domain '{domain}' is on the known malicious URL blacklist"],
            "features": extract_features(url),
            "timestamp": datetime.now().isoformat(),
        }

    # 2. ML/heuristic analysis
    features = extract_features(url)
    risk_score, reasons = ml_score(features)

    if risk_score >= 0.65:
        verdict = "SUSPICIOUS"
        confidence = "High" if risk_score >= 0.80 else "Medium"
    elif risk_score >= 0.35:
        verdict = "POTENTIALLY SUSPICIOUS"
        confidence = "Low"
    else:
        verdict = "SAFE"
        confidence = "High" if risk_score < 0.15 else "Medium"
        if not reasons:
            reasons = ["No suspicious signals detected"]

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": round(risk_score, 3),
        "confidence": confidence,
        "method": "ML Heuristics",
        "reasons": reasons,
        "features": features,
        "timestamp": datetime.now().isoformat(),
    }


# ─── ROUTES ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check_url():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "Empty URL"}), 400
    result = analyze_url(url)
    return jsonify(result)


@app.route("/api/batch", methods=["POST"])
def batch_check():
    data = request.get_json()
    if not data or "urls" not in data:
        return jsonify({"error": "No URLs provided"}), 400
    results = [analyze_url(u) for u in data["urls"][:20]]  # max 20
    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(debug=True, port=5000)

"""
Cyber_Phishing_Detector
Safe-by-design URL analysis: it analyzes the URL string only and does
not visit, crawl, submit forms to, or execute content from the target.
"""

import ipaddress
import re
from urllib.parse import urlparse
from math import log2

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml",
    "cf", "ga", "buzz", "cam", "rest"
}

BRAND_WORDS = {
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "instagram", "facebook", "linkedin", "whatsapp", "bank", "secure"
}

def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    n = len(text)
    return -sum((v / n) * log2(v / n) for v in counts.values())

def normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url

def extract_features(raw_url: str) -> dict:
    url = normalize(raw_url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""
    full = url.lower()

    try:
        ipaddress.ip_address(host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    labels = [x for x in host.split(".") if x]
    tld = labels[-1] if len(labels) >= 2 else ""

    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": full.count("."),
        "hyphen_count": full.count("-"),
        "underscore_count": full.count("_"),
        "slash_count": full.count("/"),
        "question_count": full.count("?"),
        "ampersand_count": full.count("&"),
        "equals_count": full.count("="),
        "at_count": full.count("@"),
        "percent_count": full.count("%"),
        "digit_count": sum(c.isdigit() for c in full),
        "subdomain_count": max(len(labels) - 2, 0),
        "uses_ip": uses_ip,
        "has_https": int(p.scheme.lower() == "https"),
        "has_port": int(p.port is not None) if p.hostname else 0,
        "is_shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "brand_in_host": int(any(b in host for b in BRAND_WORDS)),
        "brand_in_path": int(any(b in path.lower() for b in BRAND_WORDS)),
        "has_login_words": int(any(w in full for w in (
            "login", "signin", "verify", "verification", "account",
            "password", "credential", "update", "confirm", "secure"
        ))),
        "has_redirect_words": int(any(w in full for w in (
            "redirect", "url=", "next=", "return=", "continue="
        ))),
        "entropy": round(entropy(host), 4),
        "punycode": int("xn--" in host),
        "double_slash_path": int("//" in path),
    }

def analyze_url(raw_url: str) -> dict:
    if not raw_url or len(raw_url) > 4096:
        return {"error": "Enter a URL between 1 and 4096 characters."}

    url = normalize(raw_url)
    p = urlparse(url)
    if not p.hostname:
        return {"error": "The supplied value does not contain a valid hostname."}

    f = extract_features(raw_url)

    reasons = []
    score = 0

    def add(condition, points, reason):
        nonlocal score
        if condition:
            score += points
            reasons.append(reason)

    add(f["uses_ip"], 22, "The hostname is an IP address.")
    add(not f["has_https"], 10, "The URL does not use HTTPS.")
    add(f["is_shortener"], 16, "The hostname is a known URL-shortening service.")
    add(f["suspicious_tld"], 12, "The top-level domain is commonly associated with abuse reports.")
    add(f["at_count"] > 0, 18, "The URL contains an @ character.")
    add(f["punycode"], 20, "The hostname uses punycode, which can be relevant to look-alike domains.")
    add(f["url_length"] > 180, 12, "The URL is unusually long.")
    add(f["subdomain_count"] >= 3, 10, "The hostname contains many subdomain levels.")
    add(f["has_login_words"], 8, "The URL contains authentication-related keywords.")
    add(f["brand_in_host"] and f["subdomain_count"] >= 2, 12, "A recognizable brand term appears in a complex hostname.")
    add(f["brand_in_path"], 5, "A recognizable brand term appears in the path.")
    add(f["has_redirect_words"], 8, "The URL contains redirect-style parameters.")
    add(f["double_slash_path"], 8, "The path contains a double slash.")
    add(f["entropy"] > 4.0 and f["host_length"] > 20, 8, "The hostname has relatively high character entropy.")

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH RISK"
        level = "danger"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        level = "warning"
    else:
        verdict = "LOW RISK"
        level = "safe"

    return {
        "url": raw_url,
        "normalized_url": url,
        "verdict": verdict,
        "level": level,
        "risk_score": score,
        "reasons": reasons or ["No strong heuristic indicators were found."],
        "features": f,
        "note": "This is a URL-string risk assessment, not proof that a website is safe or malicious."
    }

from flask import Flask, render_template, request
import re
import tldextract
from Levenshtein import distance

app = Flask(__name__)

# Store URL history (in-memory)
url_history = []

# List of trusted brands/domains
TRUSTED_DOMAINS = ["amazon", "google", "facebook", "apple", "microsoft", "flipkart"]

# List of common URL shortening services
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]

# Suspicious keywords in URL path or query
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "bank", "update", "confirm", "account"]

def extract_domain(url):
    """Extract the main domain from a URL"""
    extracted = tldextract.extract(url)
    return extracted.domain.lower()

def check_typosquatting(domain):
    """Check if domain is similar to a trusted brand"""
    for brand in TRUSTED_DOMAINS:
        if distance(domain, brand) <= 2:  # allow 1-2 character typos
            return brand
    return None

def check_phishing(url):
    """Main phishing detection function with multiple heuristics"""
    score = 0
    reasons = []

    domain = extract_domain(url)

    # 1. IP address in URL
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url):
        score += 2
        reasons.append("URL contains an IP address instead of domain")

    # 2. HTTPS check
    if not url.startswith("https"):
        score += 1
        reasons.append("URL does not use HTTPS")

    # 3. Typosquatting / similarity to trusted brands
    fake_brand = check_typosquatting(domain)
    if fake_brand:
        score += 3
        reasons.append(f"Domain is similar to trusted brand: {fake_brand}")

    # 4. Suspicious keywords in URL
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword found: {word}")

    # 5. URL length
    if len(url) > 70:
        score += 1
        reasons.append("URL is unusually long")

    # 6. Multiple subdomains
    if url.count('.') > 3:
        score += 1
        reasons.append("URL has multiple subdomains")

    # 7. Shortened URL detection
    for short in SHORTENERS:
        if short in url.lower():
            score += 2
            reasons.append(f"URL uses a shortening service: {short}")

    # Determine result based on score
    if score >= 2:  # Threshold for phishing
        result = "PHISHING / FAKE WEBSITE ❌"
    else:
        result = "LEGITIMATE WEBSITE ✅"

    return result, reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []

    if request.method == "POST":
        url = request.form["url"]
        result, reasons = check_phishing(url)

        # Save to history (latest 5 URLs)
        url_history.insert(0, (url, result))
        if len(url_history) > 5:
            url_history.pop()

    return render_template(
        "index.html",
        result=result,
        reasons=reasons,
        history=url_history
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

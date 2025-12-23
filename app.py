from flask import Flask, render_template, request, redirect, url_for
import re
import tldextract
from Levenshtein import distance

app = Flask(__name__)

# In-memory history
url_history = []

# Trusted domains, URL shorteners, suspicious keywords
TRUSTED_DOMAINS = ["amazon", "google", "facebook", "apple", "microsoft", "flipkart"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "bank", "update", "confirm", "account"]

# -------------------- Helper Functions --------------------
def extract_domain(url):
    extracted = tldextract.extract(url)
    return extracted.domain.lower()

def check_typosquatting(domain):
    for brand in TRUSTED_DOMAINS:
        if domain != brand and distance(domain, brand) <= 2:
            return brand
    return None

def check_phishing(url):
    score = 0
    reasons = []

    domain = extract_domain(url)

    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url):
        score += 3
        reasons.append("URL contains IP address")

    fake_brand = check_typosquatting(domain)
    if fake_brand:
        score += 3
        reasons.append(f"Domain similar to trusted brand: {fake_brand}")

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 2
            reasons.append(f"Suspicious keyword found: {word}")

    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long")

    if url.count('.') > 4:
        score += 1
        reasons.append("Multiple subdomains detected")

    for short in SHORTENERS:
        if short in url.lower():
            score += 2
            reasons.append(f"URL uses shortening service: {short}")

    if not url.startswith("https"):
        reasons.append("URL does not use HTTPS")

    result = "PHISHING / FAKE WEBSITE ❌" if score >= 3 else "LEGITIMATE WEBSITE ✅"
    return result, reasons

# -------------------- Routes --------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result, reasons = check_phishing(url)
            url_history.insert(0, (url, result))
            if len(url_history) > 5:
                url_history.pop()

    return render_template(
        "index.html",
        result=result,
        reasons=reasons,
        history=url_history
    )

@app.route("/clear-history", methods=["POST"])
def clear_history():
    url_history.clear()
    return redirect(url_for("index"))

# -------------------- Run App --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)

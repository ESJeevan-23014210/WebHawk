from flask import Flask, render_template, request
import re
import tldextract
from Levenshtein import distance

app = Flask(__name__)

# Store URL history (in-memory)
url_history = []

TRUSTED_DOMAINS = ["amazon", "google", "facebook", "apple", "microsoft", "flipkart"]

def extract_domain(url):
    extracted = tldextract.extract(url)
    return extracted.domain.lower()

def check_typosquatting(domain):
    for brand in TRUSTED_DOMAINS:
        if distance(domain, brand) == 1:
            return brand
    return None

def check_phishing(url):
    score = 0
    reasons = []

    domain = extract_domain(url)

    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url):
        score += 2
        reasons.append("URL contains IP address")

    if not url.startswith("https"):
        score += 1
        reasons.append("URL does not use HTTPS")

    fake_brand = check_typosquatting(domain)
    if fake_brand:
        score += 3
        reasons.append(f"Looks similar to trusted brand: {fake_brand}")

    suspicious_words = ["login", "verify", "secure", "bank", "update"]
    for word in suspicious_words:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword found: {word}")

    if score >= 3:
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

        # Save to history
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

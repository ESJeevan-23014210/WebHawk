from flask import Flask, render_template, request, redirect, url_for
import re
import tldextract
from Levenshtein import distance
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import ssl, socket

app = Flask(__name__)

# -------------------- In-memory history --------------------
url_history = []

# -------------------- Config --------------------
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

def is_valid_url(url):
    # Auto-add http:// if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]), url
    except:
        return False, url

def is_real_domain(url):
    """Check if domain looks valid without DNS resolution."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]  # remove port if any

        # Must contain a dot
        if "." not in domain:
            return False

        # Domain should not be only numbers
        if domain.replace(".", "").isdigit():
            return False

        # Optional: check TLD
        tld = domain.split(".")[-1]
        valid_tlds = ["com", "net", "org", "in", "edu", "gov", "io"]
        if tld.lower() not in valid_tlds:
            return False

        return True
    except:
        return False

def check_redirect(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        final_domain = extract_domain(response.url)
        if final_domain != extract_domain(url):
            return True, response.url
    except:
        return False, None
    return False, None

def ssl_check(url):
    domain = extract_domain(url)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        return True
    except:
        return False

def check_favicon(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon_link:
            icon_url = icon_link.get("href")
            if icon_url and extract_domain(icon_url) != extract_domain(url):
                return True
    except:
        pass
    return False

def check_phishing(url):
    score = 0
    reasons = []

    domain = extract_domain(url)

    # IP address
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url):
        score += 3
        reasons.append("URL contains IP address")

    # Typosquatting
    fake_brand = check_typosquatting(domain)
    if fake_brand:
        score += 3
        reasons.append(f"Domain similar to trusted brand: {fake_brand}")

    # Suspicious keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 2
            reasons.append(f"Suspicious keyword found: {word}")

    # URL length
    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long")

    # Subdomains
    if url.count('.') > 4:
        score += 1
        reasons.append("Multiple subdomains detected")

    # URL shorteners
    for short in SHORTENERS:
        if short in url.lower():
            score += 2
            reasons.append(f"URL uses shortening service: {short}")

    # HTTPS
    if not url.startswith("https"):
        reasons.append("URL does not use HTTPS")
        score += 1
    elif not ssl_check(url):
        reasons.append("HTTPS certificate invalid")
        score += 2

    # Redirect check
    redirected, final_url = check_redirect(url)
    if redirected:
        score += 2
        reasons.append(f"URL redirects to {final_url}")

    # Favicon check
    if check_favicon(url):
        score += 2
        reasons.append("Favicon domain does not match URL")

    # Determine risk
    if score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    result = "PHISHING / FAKE WEBSITE ❌" if score >= 3 else "LEGITIMATE WEBSITE ✅"
    return result, reasons, risk

# -------------------- Routes --------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk = None
    reasons = []

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            valid, url = is_valid_url(url)

            # ❌ INVALID URL FORMAT
            if not valid:
                result = "INVALID URL ⚠️"
                risk = None

            # ❌ INVALID DOMAIN
            elif not is_real_domain(url):
                result = "INVALID WEBSITE ⚠️"
                risk = None

            # ✅ VALID WEBSITE → PHISHING CHECK
            else:
                result, reasons, risk = check_phishing(url)

            # Save history
            url_history.insert(0, {
                "url": url,
                "result": result,
                "risk": risk
            })

            if len(url_history) > 5:
                url_history.pop()

    return render_template(
        "index.html",
        result=result,
        risk=risk,
        reasons=reasons,
        history=url_history
    )

@app.route("/clear-history", methods=["POST"])
def clear_history():
    url_history.clear()
    return redirect(url_for("index"))

@app.route("/about")
def about():
    return render_template("about.html")

# -------------------- Run App --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)

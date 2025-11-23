from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re

app = Flask(__name__)
CORS(app)

# -------------------------------------------------------
# 1) Vulnerability Scan + Score
# -------------------------------------------------------
@app.route('/api/vuln-scan', methods=['POST'])
def vuln_scan():
    url = request.json.get('url')
    issues = []
    score = 100

    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        headers = response.headers

        # Rule checks
        checks = {
            "Content-Security-Policy": 25,
            "Strict-Transport-Security": 25,
            "X-Frame-Options": 25,
            "X-Content-Type-Options": 25
        }

        for header, penalty in checks.items():
            if header not in headers:
                issues.append(f"Missing: {header}")
                score -= penalty

        if response.status_code != 200:
            issues.append(f"Non-200 Status Code: {response.status_code}")
            score -= 10

        if score < 0: 
            score = 0

        if len(issues) == 0:
            issues.append("No major vulnerabilities detected ✔")

    except:
        issues.append("Website could not be scanned — unreachable.")
        score = 0

    return jsonify({
        "url": url,
        "issues_found": issues,
        "score": score
    })


# -------------------------------------------------------
# 2) Cookie Scanner
# -------------------------------------------------------
@app.route('/api/cookie-scan', methods=['POST'])
def cookie_scan():
    url = request.json.get('url')
    cookies_out = []

    try:
        response = requests.get(url, timeout=5)
        raw = response.headers.get("Set-Cookie")

        if raw:
            for item in raw.split(";"):
                cookies_out.append({"cookie": item.strip()})
        else:
            cookies_out.append({"cookie": "No cookies found"})
    except:
        cookies_out.append({"cookie": "Cookie scan failed"})

    return jsonify({"url": url, "cookies": cookies_out})

# ---------------------------
# 3) Improved Phishing Check
# ---------------------------
@app.route('/api/phishing-check', methods=['POST'])
def phishing_check():
    data = request.json
    url = data.get('url')

    suspicious = False
    reasons = []

    try:
        domain = url.split("//")[-1].split("/")[0].lower()

        # 1. Contains @ symbol
        if "@" in url:
            suspicious = True
            reasons.append(
                "The URL contains an '@' symbol — attackers use this to mislead users into trusting fake redirect links."
            )

        # 2. Hyphens in domain
        if "-" in domain:
            suspicious = True
            reasons.append(
                "The domain contains '-' symbols — often used to imitate legitimate brands."
            )

        # 3. Unusually long URL
        if len(url) > 85:
            suspicious = True
            reasons.append(
                "The URL is unusually long — attackers hide malicious code in long URLs."
            )

        # 4. Too many subdomains
        if domain.count(".") > 3:
            suspicious = True
            reasons.append(
                "The website uses many subdomains — a common trick to impersonate trusted websites."
            )

        # 5. Domain contains numbers
        if any(char.isdigit() for char in domain):
            suspicious = True
            reasons.append(
                "The domain contains numbers — temporary malicious domains often use numbers."
            )

        # 6. Suspicious TLDs
        risky_tlds = ["tk", "ml", "cf", "gq", "ga"]
        if any(domain.endswith("." + tld) for tld in risky_tlds):
            suspicious = True
            reasons.append(
                "The website uses a high-risk TLD extension — frequently abused by phishing attackers."
            )

        # 7. No HTTPS
        if url.startswith("http://"):
            suspicious = True
            reasons.append(
                "The website does not use HTTPS — phishing sites usually avoid SSL certificates."
            )

        # If NOTHING triggered
        if not suspicious:
            reasons.append("This URL does not show common signs of phishing. It appears safe ✓")

    except Exception as e:
        reasons.append(f"Phishing check failed: {str(e)}")

    return jsonify({
        "url": url,
        "suspicious": suspicious,
        "reasons": reasons
    })

                   

if __name__ == "__main__":
    app.run(debug=True)

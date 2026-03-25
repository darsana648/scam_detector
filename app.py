from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

def detect_scam(text):
    score = 0
    reasons = []
    text_lower = text.lower()

    # 1. Authority words
    authority_words = ["rto", "bank", "government", "police", "morth", "court"]
    if any(word in text_lower for word in authority_words):
        score += 10
        reasons.append("Mentions authority")

    # 2. Suspicious urgency
    urgency_words = [
        "urgent", "immediately", "action", "pay now", "click",
        "blocked", "suspended", "verify", "within", "limited time"
    ]
    if any(word in text_lower for word in urgency_words):
        score += 15
        reasons.append("Creates urgency")

    # 3. Account/security context
    security_words = ["account", "login", "security", "password", "verify"]
    if any(word in text_lower for word in security_words):
        score += 10
        reasons.append("Account/security related")

    # 4. Link detection (ADVANCED 🔥)
    links = re.findall(r'https?://\S+', text)

    if links:
        for link in links:
            domain = urlparse(link).netloc.lower()

            # 🟢 HIGH TRUST (government)
            if domain.endswith("gov.in") or domain.endswith("nic.in"):
                score -= 40
                reasons.append(f"Government domain: {domain}")

            # 🟡 MEDIUM TRUST (brands - flexible)
            elif any(brand in domain for brand in [
                "amazon", "flipkart", "myntra", "meesho", "ajio", "nykaa",
                "sbi", "hdfc", "icici", "axis", "kotak",
                "google", "microsoft", "apple"
            ]):
                score -= 15
                reasons.append(f"Recognized brand: {domain}")

            # 🔴 SUSPICIOUS structure
            elif "-" in domain or "@" in domain or domain.count('.') > 3:
                score += 40
                reasons.append(f"Suspicious domain structure: {domain}")

            # ⚠️ UNKNOWN domain
            else:
                score += 25
                reasons.append(f"Unknown domain: {domain}")

    # 5. Money mention
    if "rs" in text_lower or "₹" in text_lower:
        score += 10
        reasons.append("Mentions payment")

    # 6. Vehicle + challan pattern
    if "vehicle" in text_lower and "challan" in text_lower:
        score += 10
        reasons.append("Challan-related message")

        if "parivahan" in text_lower:
            score -= 15
            reasons.append("Matches official traffic format")

    # 7. Suspicious formatting
    if text.count(".") > 5 or text.count(":") > 3:
        score += 5
        reasons.append("Unusual formatting")

    # Normalize score
    score = max(0, min(score, 100))

    # Final decision
    if score > 60:
        result = "⚠️ Likely Scam"
    elif score > 35:
        result = "⚠️ Suspicious"
    else:
        result = "✅ Seems Safe"

    return result, score, reasons


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    score = None
    reasons = []

    if request.method == "POST":
        text = request.form["message"]
        result, score, reasons = detect_scam(text)

    return render_template("index.html", result=result, score=score, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)
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
        score += 15
        reasons.append("Claims to be from authority")

    # 2. Suspicious urgency
    urgency_words = ["urgent", "immediately", "action", "pay now", "click"]
    if any(word in text_lower for word in urgency_words):
        score += 20
        reasons.append("Creates urgency")

    # 3. Link detection
    links = re.findall(r'https?://\S+', text)
    if links:
        score += 20
        reasons.append("Contains link")

        for link in links:
            domain = urlparse(link).netloc
            trusted_domains = ["parivahan.gov.in", "vcourts.gov.in"]

            if not any(domain.endswith(td) for td in trusted_domains):
                score += 25
                reasons.append(f"Untrusted domain: {domain}")

    # 4. Money mention
    if "rs" in text_lower or "₹" in text_lower:
        score += 10
        reasons.append("Mentions payment")

    # 5. Vehicle + challan pattern
    if "vehicle" in text_lower and "challan" in text_lower:
        score += 15
        reasons.append("Vehicle/challan related message")

    # 6. Suspicious formatting
    if text.count(".") > 5 or text.count(":") > 3:
        score += 10
        reasons.append("Unusual formatting pattern")

    score = min(score, 100)

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
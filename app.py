from flask import Flask, render_template, request

app = Flask(__name__)

def detect_scam(text):
    score = 0
    reasons = []

    text = text.lower()

    # Keywords
    scam_words = ["win", "prize", "urgent", "click", "offer", "free", "money", "lottery"]

    for word in scam_words:
        if word in text:
            score += 10
            reasons.append(f"Contains suspicious word: {word}")

    # Check links
    if "http" in text or "www" in text:
        score += 20
        reasons.append("Contains link")

    # Check money symbol
    if "₹" in text or "$" in text:
        score += 15
        reasons.append("Mentions money")

    # Final decision
    if score > 40:
        result = "⚠️ Scam Detected"
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
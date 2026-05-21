"""
Simple Flask web interface for the Phishing URL Detection Tool.
"""

from flask import Flask, render_template, request

from detector import analyze_url


app = Flask(__name__)
history = []


@app.route("/")
def index():
    """Show the URL input form."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze the submitted URL and show the result page."""
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", error="Please enter a URL.")

    result = analyze_url(url)
    history.append(
        {
            "url": result["url"],
            "score": result["score"],
            "risk_level": result["risk_level"],
        }
    )

    newest_first_history = list(reversed(history))
    return render_template(
        "result.html",
        result=result,
        history=newest_first_history,
    )


if __name__ == "__main__":
    app.run(debug=True)

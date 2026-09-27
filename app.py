from flask import Flask, render_template, request, jsonify
from detector import analyze_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = analyze_url(url)
    return render_template("index.html", result=result, url=url)

@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(analyze_url(url))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

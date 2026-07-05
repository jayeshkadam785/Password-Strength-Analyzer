"""
app.py
Flask web interface for the Password Strength Analyzer.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify

from analyzer import analyze_password, suggest_strong_password
from database import init_db, is_password_reused, save_password

app = Flask(__name__)
init_db()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(force=True) or {}
    password = data.get("password", "")
    username = data.get("username", "").strip()

    if not password:
        return jsonify({"error": "Password is required."}), 400

    result = analyze_password(password, user_inputs=[username])

    reused = False
    if username:
        reused = is_password_reused(username, password)
        if reused:
            result["suggestions"].insert(
                0, "You've used this password before — please choose a new one."
            )
            result["score"] = 0
            result["label"] = "Reused Password"

    result["reused"] = reused
    return jsonify(result)


@app.route("/api/save", methods=["POST"])
def api_save():
    """Call this once a strong, non-reused password is accepted, to record its hash."""
    data = request.get_json(force=True) or {}
    password = data.get("password", "")
    username = data.get("username", "").strip()

    if not password or not username:
        return jsonify({"error": "username and password are required."}), 400

    if is_password_reused(username, password):
        return jsonify({"error": "Password was used before. Not saved."}), 409

    save_password(username, password)
    return jsonify({"status": "saved"})


@app.route("/api/suggest", methods=["GET"])
def api_suggest():
    length = int(request.args.get("length", 16))
    return jsonify({"password": suggest_strong_password(length)})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

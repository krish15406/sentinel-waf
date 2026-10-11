
import csv
import os
from flask import Flask, request, jsonify
from waf_engine import inspect_request

app = Flask(__name__)

LOG_FILE = "waf_logs.csv"
LOG_FIELDS = [
    "timestamp", "method", "path", "ip",
    "status", "attack_type", "action"
]


def save_log(record):
    file_exists = os.path.exists(LOG_FILE)

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=LOG_FIELDS)

        if not file_exists or os.path.getsize(LOG_FILE) == 0:
            writer.writeheader()

        writer.writerow(record)


@app.before_request
def protect_request():
    raw_body = request.get_data(as_text=True)
    query_data = request.query_string.decode(
        "utf-8", errors="replace"
    )
    decoded_params = str(dict(request.args))

    result = inspect_request(
        method=request.method,
        path=request.path,
        data=f"{query_data} {decoded_params} {raw_body}",
        ip=request.remote_addr or "unknown",
    )

    save_log(result)

    if result["status"] == "BLOCKED":
        return jsonify({
            "message": "Request blocked by SENTINEL WAF",
            "attack_type": result["attack_type"],
            "action": "Block",
        }), 403


@app.route("/")
def home():
    return jsonify({
        "application": "SENTINEL WAF",
        "message": "Welcome! Your request passed the WAF."
    })


@app.route("/search")
def search():
    return jsonify({
        "message": "Search request allowed",
        "query": request.args.get("q", "")
    })


@app.route("/logs")
def logs():
    records = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline="", encoding="utf-8") as file:
            records = list(csv.DictReader(file))

    return jsonify(records)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)

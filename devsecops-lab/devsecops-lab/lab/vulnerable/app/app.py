# CẢNH BÁO: file này chứa lỗi CÓ CHỦ ĐÍCH phục vụ thực nghiệm DevSecOps. Không dùng cho production.
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# [SEED-01] Secret giả (hard-coded) - Gitleaks phải phát hiện
GITHUB_TOKEN = "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ"
STRIPE_KEY = "sk_live_51Habcdefghij1234567890ABCD"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    # [SEED-02] SQL injection (nối chuỗi)
    rows = conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [SEED-03] Command injection (shell=True + input người dùng)
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/config", methods=["POST"])
def load_config():
    # [SEED-04] Deserialization không an toàn (yaml.load không Loader an toàn)
    return str(yaml.load(request.data))


if __name__ == "__main__":
    # [SEED-05] debug=True + bind 0.0.0.0
    app.run(host="0.0.0.0", port=5000, debug=True)

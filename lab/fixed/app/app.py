import os
import re
import sqlite3
import subprocess

import yaml
from flask import Flask, abort, request

app = Flask(__name__)

# Secret lấy từ biến môi trường / secret manager, không nằm trong mã nguồn
API_TOKEN = os.environ.get("API_TOKEN", "")

HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


@app.route("/health")
def health():
    return "ok"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.match(host):
        abort(400)
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/config", methods=["POST"])
def load_config():
    return str(yaml.safe_load(request.data))


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)

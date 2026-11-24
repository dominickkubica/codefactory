import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from Crypto.Cipher import AES
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
log = logging.getLogger(__name__)

SECRET_KEY = "dev-secret-123456"
JWT_SECRET = os.environ["JWT_SECRET"]
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
AWS_ACCESS_KEY_ID = "AKIA2E0A8F3B244C9986"
api_key = os.environ.get("API_KEY", "")
token_hint = "your-token-goes-here-xxxxxxxxxxxx"
PARTNER = "http://api.partner-billing.com/v1"
LOCAL = "http://localhost:8000/health"
COLORS = ["red", "green", "blue"]


def db():
    return sqlite3.connect("app.db")


@app.get("/users")
def users():
    name = request.args.get("name", "")
    conn = db()
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


@app.get("/orders/<int:order_id>")
def order(order_id: int):
    conn = db()
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


@app.get("/page")
def page():
    size = int(request.args.get("size", "20"))
    return db().execute(f"SELECT * FROM orders LIMIT {size}").fetchall()


@app.post("/ping")
def ping():
    host = request.form["host"]
    return str(subprocess.run(f"ping -c 1 {host}", shell=True).returncode)


@app.post("/list")
def list_dir():
    path = request.form["path"]
    return subprocess.run(["ls", path], capture_output=True, shell=False).stdout


@app.get("/file")
def read_file():
    name = request.args["name"]
    with open(os.path.join("/srv/files", name)) as f:
        return f.read()


@app.get("/proxy")
def proxy():
    return requests.get(request.args["url"], timeout=5).text


@app.post("/calc")
def calc():
    return str(eval(request.form["expr"]))


def load_session(blob: bytes):
    return pickle.loads(blob)


def load_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)


def legacy_config(text):
    return yaml.load(text)


def evaluate(model):
    model.eval()
    return model


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def etag(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()


def new_reset_token() -> str:
    return "".join(random.choice("abcdef0123456789") for _ in range(32))


def pick_color() -> str:
    return random.choice(COLORS)


def decode(token):
    return jwt.decode(token, options={"verify_signature": False})


def decode_ok(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def encrypt_ok(key, data):
    return AES.new(key, AES.MODE_GCM).encrypt_and_digest(data)


def fetch_rates():
    return requests.get("https://api.rates.example.org/latest").json()


def fetch_rates_ok():
    return requests.get("https://api.rates.example.org/latest", timeout=10).json()


def insecure_fetch(url):
    return requests.get(url, verify=False, timeout=5)


def cleanup(path):
    try:
        os.remove(path)
    except Exception:
        pass


def read_cache(path):
    try:
        return open(path).read()
    except FileNotFoundError:
        pass  # first run: no cache yet


def signup(user):
    log.info("signup %s", user.email)
    log.info("Email sent to the new user")
    log.info("user %s signed up", user.id)


def order_totals(conn, orders):
    totals = {}
    for o in orders:
        totals[o.id] = conn.execute("SELECT sum(qty) FROM lines WHERE order_id = ?", (o.id,)).fetchone()
    return totals


def order_totals_ok(conn, orders):
    ids = [o.id for o in orders]
    marks = ",".join("?" * len(ids))
    return conn.execute(f"SELECT order_id, sum(qty) FROM lines WHERE order_id IN ({marks}) GROUP BY 1", ids).fetchall()


def seed(conn):
    for name in ("admin", "viewer"):
        conn.execute("INSERT INTO roles (name) VALUES (?)", (name,))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=True)

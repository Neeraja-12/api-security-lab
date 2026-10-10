"""
SECURE VERSION - api-security-lab
Fixes OWASP API Top 10 (2023) issues documented in FINDINGS.md.
Run locally only.
"""

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import sqlite3
import jwt
import datetime
import os
import re
import ipaddress
from urllib.parse import urlparse
import bcrypt

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET", os.urandom(32).hex())
DB_PATH = "users.db"

# FIX: rate limiting on login and other endpoints
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            ssn TEXT,
            is_admin INTEGER DEFAULT 0,
            balance REAL DEFAULT 1000
        );
        """
    )
    conn.commit()
    conn.close()


def hash_pw(pw):
    # FIX: bcrypt instead of MD5
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_pw(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


def seed():
    conn = get_db()
    users = [
        ("alice", hash_pw("alice123"), "alice@example.com", "111-11-1111", 0, 5000),
        ("bob",   hash_pw("bob123"),   "bob@example.com",   "222-22-2222", 0, 3000),
        ("admin", hash_pw("admin123"), "admin@example.com", "333-33-3333", 1, 99999),
    ]
    for u in users:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, email, ssn, is_admin, balance) "
                "VALUES (?,?,?,?,?,?)", u)
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()


# ---------- AUTH ----------
def make_token(user_id, is_admin):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "user_id": user_id,
        "is_admin": bool(is_admin),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=15),  # FIX: expiry
        "aud": "api-security-lab",
        "iss": "api-security-lab",
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        data = jwt.decode(
            token,
            app.config["SECRET_KEY"],
            algorithms=["HS256"],          # FIX: algorithm pinning
            audience="api-security-lab",
            issuer="api-security-lab",
        )
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def is_admin_from_db(user_id):
    # FIX: check admin from DB, not JWT claim
    conn = get_db()
    row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return bool(row and row["is_admin"])


def serialize_user(row, include_private=False):
    # FIX: explicit response shape
    base = {"id": row["id"], "username": row["username"], "email": row["email"]}
    if include_private:
        base["balance"] = row["balance"]
    return base


# ---------- ROUTES ----------
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")           # FIX: brute-force protection
def login():
    body = request.get_json() or {}
    username = body.get("username")
    password = body.get("password")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row or not verify_pw(password or "", row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    token = make_token(row["id"], row["is_admin"])
    return jsonify({"token": token})


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    me = current_user()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    # FIX: BOLA - only self or admin
    if me["user_id"] != user_id and not is_admin_from_db(me["user_id"]):
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(serialize_user(row, include_private=(me["user_id"] == user_id)))


@app.route("/admin/users", methods=["GET"])
def admin_users():
    me = current_user()
    if not me or not is_admin_from_db(me["user_id"]):    # FIX: DB check
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([serialize_user(r, include_private=True) for r in rows])


@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    me = current_user()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    # FIX: only self or admin
    if me["user_id"] != user_id and not is_admin_from_db(me["user_id"]):
        return jsonify({"error": "forbidden"}), 403
    body = request.get_json() or {}
    # FIX: whitelist safe fields only
    allowed = ["email"]
    sets, values = [], []
    for k in allowed:
        if k in body:
            sets.append(f"{k}=?")
            values.append(body[k])
    if not sets:
        return jsonify({"error": "nothing to update"}), 400
    values.append(user_id)
    conn = get_db()
    conn.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", values)
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"})


# ---------- SSRF-safe fetch ----------
BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

ALLOWED_SCHEMES = {"http", "https"}

def is_url_safe(url):
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES:
        return False, "scheme not allowed"
    host = p.hostname
    if not host:
        return False, "no host"
    try:
        ip = ipaddress.ip_address(host)
        for net in BLOCKED_NETS:
            if ip in net:
                return False, "private address blocked"
    except ValueError:
        # hostname, not an IP - resolved at request time by requests;
        # for full safety, resolve DNS first and check each IP
        pass
    return True, "ok"


@app.route("/fetch", methods=["GET"])
def fetch():
    me = current_user()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url required"}), 400
    ok, reason = is_url_safe(url)
    if not ok:
        return jsonify({"error": f"blocked: {reason}"}), 400
    try:
        import requests
        r = requests.get(url, timeout=5, allow_redirects=False)   # FIX: no redirects
        return jsonify({"status": r.status_code, "body": r.text[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    seed()
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)   # FIX: debug off by default
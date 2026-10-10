"""
INTENTIONALLY VULNERABLE API - FOR LOCAL SECURITY TRAINING ONLY.
DO NOT DEPLOY THIS TO THE INTERNET.
Vulnerabilities map to OWASP API Security Top 10 (2023).
"""

from flask import Flask, request, jsonify
import sqlite3
import jwt
import requests
import hashlib

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret123"   # VULN: weak secret
DB_PATH = "users.db"


# ------------------------- DB HELPERS -------------------------
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
    return hashlib.md5(pw.encode()).hexdigest()   # VULN: MD5


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


# ------------------------- AUTH -------------------------
def make_token(user_id, is_admin):
    payload = {
        "user_id": user_id,
        "is_admin": is_admin,
        # VULN: no exp, no iat, no audience
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        # VULN: accepts "none" and HS256, no algorithm pinning
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256", "none"])
        return data
    except Exception:
        return None


# ------------------------- ROUTES -------------------------
@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    username = body.get("username")
    password = body.get("password")
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, hash_pw(password or "")),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    token = make_token(row["id"], row["is_admin"])
    return jsonify({"token": token})


# VULN: BOLA - any logged-in user can read ANY user's record
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    # VULN: Excessive Data Exposure - returns password hash + SSN
    return jsonify(dict(row))


# VULN: Broken Function Level Authorization
@app.route("/admin/users", methods=["GET"])
def admin_users():
    user = current_user()
    if not user or not user.get("is_admin"):
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# VULN: Mass Assignment - accepts is_admin and balance
@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json() or {}
    allowed = ["email", "username", "is_admin", "balance"]
    sets = []
    values = []
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


# VULN: SSRF
@app.route("/fetch", methods=["GET"])
def fetch():
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        r = requests.get(url, timeout=5)
        return jsonify({"status": r.status_code, "body": r.text[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    seed()
    app.run(host="0.0.0.0", port=5000, debug=True)   # VULN: debug in prod
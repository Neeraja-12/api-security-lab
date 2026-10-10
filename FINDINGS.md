# Security Findings Report

Project: api-security-lab
Author: Routhu Neeraja
Standard: OWASP API Security Top 10 (2023)

---

## Finding 1 — BOLA (Broken Object Level Authorization)
- **OWASP API Top 10:** API1:2023
- **Endpoint:** `GET /users/<id>`
- **Severity:** High
- **Steps to reproduce:**
  1. Login as `alice` and capture the JWT.
  2. Send `GET /users/2` with alice's token.
  3. Observe Bob's record is returned.
- **Impact:** Any authenticated user can read any other user's data.
- **Fix:** Verify `token.user_id == requested user_id` OR caller is admin.

---

## Finding 2 — Broken Authentication (Weak JWT)
- **OWASP API Top 10:** API2:2023
- **Endpoint:** `POST /login`
- **Severity:** High
- **Details:**
  - Weak hardcoded secret `supersecret123`
  - No `exp`, `iat`, or `aud` claims
  - `algorithms=["HS256","none"]` allows algorithm confusion
- **Impact:** Attacker can forge tokens and impersonate any user, including admin.
- **Fix:** Load secret from env, add `exp` (15 min), pin algorithms to `["HS256"]`.

---

## Finding 3 — Excessive Data Exposure
- **OWASP API Top 10:** API3:2023
- **Endpoint:** `GET /users/<id>`
- **Severity:** High
- **Details:** Response includes `password_hash`, `ssn`, `is_admin`, `balance`.
- **Impact:** Sensitive PII and credential hashes exposed to clients.
- **Fix:** Return only `id`, `username`, `email` via serializer.

---

## Finding 4 — Mass Assignment
- **OWASP API Top 10:** API3 / API6:2023
- **Endpoint:** `PUT /users/<id>`
- **Severity:** Critical
- **Steps:**
  ```bash
  curl -X PUT http://localhost:5000/users/1 \
    -H "Authorization: Bearer <ALICE_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"is_admin":1, "balance":999999}'
  ```
- **Impact:** Any user can promote themselves to admin.
- **Fix:** Whitelist only safe fields (`email`).

---

## Finding 5 — Broken Function Level Authorization
- **OWASP API Top 10:** API5:2023
- **Endpoint:** `GET /admin/users`
- **Severity:** High
- **Details:** Admin check trusts the JWT claim only.
- **Fix:** Re-fetch `is_admin` from the database on every admin request.

---

## Finding 6 — SSRF
- **OWASP API Top 10:** API7:2023
- **Endpoint:** `GET /fetch?url=`
- **Severity:** High
- **Steps:**
  ```bash
  curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/" \
    -H "Authorization: Bearer <ALICE_TOKEN>"
  ```
- **Impact:** Leaks cloud metadata / IAM credentials in cloud environments.
- **Fix:** Allowlist domains, block private IP ranges, disable redirects.

---

## Finding 7 — No Rate Limiting on Login
- **OWASP API Top 10:** API4:2023
- **Endpoint:** `POST /login`
- **Severity:** Medium
- **Impact:** Allows unlimited password brute-force attempts.
- **Fix:** Add `Flask-Limiter` (5 attempts/min per IP).

---

## Remediation Summary
All findings are fixed in the `secure` branch:
- BOLA → ownership check
- JWT → env secret, exp, algorithm pinning
- Data exposure → response serializer
- Mass assignment → field whitelist
- Admin authz → DB check
- SSRF → allowlist + private IP block
- Rate limiting → Flask-Limiter
- Password hashing → bcrypt
- Debug mode → off
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
- **Fix commit:** `secure` branch

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
- **Fix commit:** `secure` branch

---

## Finding 3 — Excessive Data Exposure
- **OWASP API Top 10:** API3:2023
- **Endpoint:** `GET /users/<id>`
- **Severity:** High
- **Details:** Response includes `password_hash`, `ssn`, `is_admin`, `balance`.
- **Impact:** Sensitive PII and credential hashes exposed to clients.
- **Fix:** Return only `id`, `username`, `email` via serializer.
- **Fix commit:** `secure` branch

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
# API Security Lab (Intentionally Vulnerable)

⚠️ **WARNING:** This API is intentionally insecure and is meant to be run
**only on your local machine** for security training. Never deploy it publicly.

## Purpose
Hands-on lab covering the OWASP API Security Top 10 (2023).

## Vulnerabilities included

| # | Vulnerability | OWASP API Top 10 (2023) | Endpoint |
|---|---------------|-------------------------|----------|
| 1 | BOLA — read any user by ID | API1 | GET /users/<id> |
| 2 | Broken Authentication (weak JWT, no exp) | API2 | POST /login |
| 3 | Excessive Data Exposure (hash, SSN) | API3 | GET /users/<id> |
| 4 | Mass Assignment (is_admin, balance) | API3 / API6 | PUT /users/<id> |
| 5 | Broken Function Level Authorization | API5 | GET /admin/users |
| 6 | SSRF | API7 | GET /fetch?url= |
| 7 | No rate limiting on login | API4 | POST /login |

## Run locally

```bash
docker compose up --build
```

API is at `http://localhost:5000`.

## Seed users

| username | password |
|----------|----------|
| alice | alice123 |
| bob | bob123 |
| admin | admin123 |

## Example requests

```bash
# Login as alice
curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'

# Read Bob's data as alice (BOLA)
curl -s http://localhost:5000/users/2 \
  -H "Authorization: Bearer <ALICE_TOKEN>"
```

## Fix plan
Each vulnerability is patched in the `secure` branch. See `FINDINGS.md`.

## Tools used
- Postman
- Burp Suite Community
- OWASP ZAP
- Python / Flask
- Docker

## Disclaimer
For educational purposes only. Do not deploy publicly.

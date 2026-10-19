# SecureWallet: Spec (as built)

Mini secure fintech wallet for CY-5004 Assignment 1.
Stack: **FastAPI** (Python 3.12) · **PostgreSQL 16** · **React 18 + Vite** · **nginx** · **Docker Compose**.
Money is integer **paisa** (`BIGINT`) end to end. No floats in any money path.

The brief says: *"A smaller number of well-selected and properly justified controls is preferable."*
So the design has **10 weaknesses with 10 controls**. Each control maps to a question in the brief, has a
before/after demo in the Security Lab, and has an automated test (`backend/tests/test_security.py`).

---

## 1. Architecture

```
Browser (React SPA)          edge network                         internal network (no internet, no published ports)
┌─────────────────────┐     ┌──────────────────────┐            ┌────────────────────────┐      ┌──────────────────────────┐
│ Wallet UI           │────▶│ nginx :8080          │───/api────▶│ FastAPI (uvicorn)      │─────▶│ PostgreSQL 16            │
│ Presenter tools:    │     │ static SPA           │            │ runs as DB role        │      │ RLS policies             │
│  · Security trace   │     │ strict CSP, headers  │            │ wallet_app (NOBYPASS-  │      │ transfer_funds() SECURITY│
│  · Security lab     │     │ outer rate limit     │            │ RLS, not table owner)  │      │ DEFINER, CHECKs, grants  │
│ WebAuthn (passkeys) │     │ 32 KB body cap       │            │ keys volume (ES256)    │      │ append-only audit_log    │
└─────────────────────┘     └──────────────────────┘            └────────────────────────┘      └──────────────────────────┘
        ▲ Windows Hello / Touch ID / security key (private key never leaves the device)
```

| Layer (Lecture 2) | Where | Controls |
|---|---|---|
| L1 Trust the actor | `auth.py`, `tokens.py`, `passwords.py`, browser authenticator | argon2id, throttling + lockout, ES256 JWT, revocation, refresh rotation, FIDO2 step-up |
| L2 Validate the action | `deps.py`, `transfers.py`, `schemas.py` | scopes, roles, ownership filter, strict schemas, idempotency, risk engine |
| L3 Protect the data | `schema.sql` | RLS, least-privilege grants, `transfer_funds()` with row locks, CHECK constraints |
| L4 Contain compromise | `docker-compose.yml`, `nginx.conf` | DB on an internal network, non-root read-only containers, CSP, secrets in `.env` / volume |
| L5 Detect | `audit.py`, Audit desk | every outcome audited, redaction, append-only trigger |
| L6 Recover | `reconcile_ledger()` | balance-vs-ledger reconciliation, conservation of total supply |

---

## 2. Assets and weaknesses (Asset → Weakness → Impact → Control)

| ID | Brief's question | Asset | Weakness | Impact | CIA |
|---|---|---|---|---|---|
| W1 | Can one customer access another customer's information? | Wallet balance, transactions | BOLA / IDOR: changing an id in the URL returns someone else's wallet | Privacy breach, fraud reconnaissance | C |
| W2 | Can credentials be exposed? | Credentials | Passwords stored readable | DB leak → mass account takeover | C |
| W3 | Can unauthorized users perform sensitive operations? | Credentials, accounts | Unlimited password guessing | Account takeover | C I |
| W4 | Can unauthorized users perform sensitive operations? | Session token | Token accepted without verifying signature | Impersonate any customer | I |
| W5 | What happens if invalid input is submitted? | Wallet balance | Negative / zero / fractional / oversized amounts, extra fields | Money pulled from another wallet | I |
| W6 | Can transactions be manipulated? | Wallet balance | Replayed or double-submitted request | Customer charged twice | I |
| W7 | What happens if part of the system fails? | Balances, ledger | Race condition: parallel transfers read the same balance | Lost updates, ledger no longer adds up | I |
| W8 | Can unauthorized users perform sensitive operations? | Wallet balance | A stolen password or session can move large sums | Wallet drained | I |
| W9 | Are privileged operations separated? | Audit log | Customer can reach auditor functions | Exposure of everyone's activity | C |
| W10 | Can important actions occur without being recorded? | Audit trail | No record of rejections; secrets in logs | No accountability; credential leak | I C |

---

## 3. Security Design Table

| ID | Asset / Component | Identified weakness | Possible impact | Proposed control | How the control was implemented | Result (test) |
|---|---|---|---|---|---|---|
| W1 | Wallets, transactions / Wallet API + DB | BOLA: `GET /api/wallets/{id}` for someone else's id | Privacy breach | **Postgres Row-Level Security** plus an ownership filter in the API (defence in depth) | `schema.sql`: `ENABLE ROW LEVEL SECURITY`, policies `user_id = app_uid()`. The API runs as `wallet_app` (not owner, `NOBYPASSRLS`) and sets `SET LOCAL app.user_id` per transaction (`db.py`). `wallet.py` adds `AND w.user_id = :caller`. 404 on mismatch | Before: 200 with Sara's balance. API filter off only: still 404 (RLS). After: 404 |
| W2 | Credentials / `users` table | Readable password storage | Mass takeover after a leak | argon2id (m=64 MiB, t=3, p=2, 16 B salt); dummy verify for unknown users | `passwords.py` | Before: `plain$open-sesame-2026`. After: `$argon2id$v=19$m=65536,t=3,p=2$…` |
| W3 | Login endpoint | Unlimited guessing | Account takeover | Per-IP sliding window (20/min), per-account lockout (5 failures → 60 s, doubling to 15 min), identical error message, nginx outer limit | `ratelimit.py`, `auth.py`, `nginx.conf` | Before: 10 wrong then the right password gives 200. After: 429 on the 6th attempt, and the right password is refused while locked |
| W4 | Access token | Forged `sub` accepted | Impersonation | ES256 JWS with the alg pinned, `kid`, `iss/aud/exp/nbf/iat/jti` required, revocation list on logout, rotating refresh token with reuse detection | `tokens.py`, `deps.py` | Before: forged token → 200 as Sara. After: 401. `alg:none` → 401 |
| W5 | Transfer API | Invalid amounts, mass assignment | Money pulled from another wallet | Pydantic strict schema (`extra=forbid`, `StrictInt`), server rules, and re-validation inside `transfer_funds()` plus `CHECK (amount > 0)` | `schemas.py`, `transfers.py`, `schema.sql` | Before: −Rs 5,000 → 201 and the sender's balance goes up. After: 422 |
| W6 | Transfer API | Replay / double submit | Paying twice | `Idempotency-Key` header; `(user_id, key)` primary key; the stored response is replayed; same key with a different body → 409 | `transfers.py`, `idempotency_keys` | Before: 5 identical requests → charged 5×. After: charged once |
| W7 | Balances, ledger | Race condition | Lost updates, money created | All money moves through one `SECURITY DEFINER` function: both wallets locked `FOR UPDATE` in a fixed order, then debit + credit + insert in one DB transaction; `CHECK (balance >= 0)`; the app role has no UPDATE on wallets | `transfer_funds()` in `schema.sql` | Before: 10 parallel transfers recorded, balance fell less, reconcile fails. After: exact, and reconcile passes |
| W8 | High-value transfers | Stolen session is enough | Wallet drained | Risk engine (> Rs 50,000, or first payment > Rs 10,000 to a new payee) → **FIDO2 step-up**. The challenge is `SHA-256(nonce ‖ canonical transfer)`, bound to that exact transfer; UV required; origin/rpId/counter checked | `risk.py`, `transfers.py` (`/confirm`), `security/passkeys.py` | Before: Rs 60,000 → 201 with only a token. After: 202, and nothing moves without the passkey. A wrong origin or tampered challenge → 400; a replay → 409 |
| W9 | Audit desk | Customers reach privileged functions | Exposure of everyone's data | RBAC: scopes per role (`audit:read` for the auditor only, no `transfer:write`), role check in the API, and a role check inside `reconcile_ledger()` | `deps.py`, `auditing.py`, `schema.sql` | Before: customer reads the audit log (200). After: 403. Reconcile stays 403 even with the API check off |
| W10 | Audit trail | Unrecorded or secret-leaking logs | No accountability | Every outcome audited on its own connection (survives rollback); key-based redaction; append-only trigger; no stack traces to clients | `audit.py`, `main.py`, trigger in `schema.sql` | Failed login audited with the username, never the password |

**Principles (brief §8).**
- Confidentiality: W1, W2, W9.
- Integrity: W4–W8.
- Availability: throttling, and fail-closed 503 when the DB is down.
- Authentication: W2, W3, W4, W8.
- Authorization: W1, W9.
- **Least privilege:** the app DB role has no UPDATE on balances and no INSERT on transactions; scopes are per role.
- **Secure defaults:** `DEMO_MODE` is off by default, and the Lab and trace are then not mounted.
- **Separation of responsibilities:** the auditor role cannot move money; customers cannot audit.
- **Defence in depth:** the API filter plus RLS (W1); schema plus service plus DB function plus CHECK (W5); the API role check plus the DB function (W9).
- **Reduced exposure:** the DB is on an internal network, and responses carry minimal fields (a lookup returns no ids or balances).
- **Logging/accountability:** W10.
- **Resilience:** atomic transactions, idempotent retries, reconciliation.

---

## 4. Milestones

| # | Milestone | Status | Where |
|---|---|---|---|
| M0 | Docker Compose (db, api, web), roles init, internal network, non-root read-only containers | Done | `docker-compose.yml`, `db/init/01-roles.sh`, Dockerfiles |
| M1 | Schema, RLS, grants, `transfer_funds()`, `reconcile_ledger()`, seed data | Done | `backend/app/sql/schema.sql`, `migrate.py` |
| M2 | Trace collector (no-op unless demo mode + header) | Done | `trace.py`, `main.py` middleware |
| M3 | Register / login / refresh / logout, argon2id, ES256 JWT, lockout | Done | `routers/auth.py`, `security/` |
| M4 | Wallet, history, lookup, contacts with ownership + RLS | Done | `routers/wallet.py` |
| M5 | Transfers: validation, idempotency, atomic DB function | Done | `routers/transfers.py` |
| M6 | Passkeys: registration, risk engine, transfer-bound step-up | Done | `routers/passkeys.py`, `security/passkeys.py`, `risk.py` |
| M7 | Audit log, redaction, auditor desk, reconciliation | Done | `audit.py`, `routers/auditing.py` |
| M8 | Security Lab: 10 switches, real DDL for RLS/constraints, reset | Done | `lab.py`, `routers/lab.py` |
| M9 | Frontend: wallet app + hidden presenter tools (trace drawer, lab) | Done | `frontend/src` |
| M10 | Tests: 19 end-to-end tests, before/after per weakness, software FIDO2 authenticator | Done: 19/19 pass | `backend/tests` |

---

## 5. Security trace (presenter tools)

- **Turning it on:** it is hidden from normal users. Use the avatar menu → *Presenter tools*, or **Ctrl+Shift+D**. The toggle only exists when the API reports `demo_available`.
- **How it works:** when it is on, the SPA sends `X-Security-Trace: 1`. The backend records each security decision into a per-request collector (`contextvars`) and returns it as `_trace`. When it is off, the header isn't sent and `step()` is a no-op. With `DEMO_MODE=false` the server ignores the header entirely (verified).
- **Server-side steps shown with real values:**
  - bearer extraction and JWT parse (colour-coded header, payload, signature);
  - ES256 verification math, recomputed by `ecdsa_edu.py` and checked against `cryptography`: `z, w = s⁻¹, u₁, u₂, X = u₁G + u₂Q, x mod n == r`;
  - claims, revocation, scope and role checks;
  - `SET LOCAL app.user_id` for RLS, and the RLS policy with rows returned;
  - argon2id parameters and salt;
  - validation checklist and risk decision;
  - step-up challenge binding;
  - clientDataJSON checks;
  - authenticatorData byte map (rpIdHash, flags, signCount);
  - device ECDSA verification math;
  - the FIDO2 checklist;
  - the atomic transfer SQL with balances;
  - the audit record.
- **Browser-side steps:** the `navigator.credentials.*` calls and the authenticator output are added by the SPA.
- **Presenter aids:** *Step through* reveals the newest action one step at a time (→ key); *Markdown* copies the whole trace as evidence for the report.
- **Grouping by action.** Every request is tagged at send time with the user action that triggered it: sign in, a transfer (which gets its TX reference once it completes), a passkey change, a lab attack, or a page open. The filter at the top can show:
  - one action, with a summary card listing its requests, checks, failures and total time;
  - all transfers;
  - all lab attacks.
- **Per-request details.** Each request shows its send time, its round trip and the components it touched (`Browser`, `Authenticator`, `API`, `Database`). *Explain* opens a plain-language note covering the controls involved and a talking point for the demo.

---

## 6. Demo script (~12 minutes, presenter tools on)

1. **Sign in as `ali`.** Trace: rate limit → lockout state → argon2id verify → JWT signing (z, r, s).
2. **Home → Send Rs 2,000 to Sara** (the brief's example). Trace: token verify math → scope → RLS identity → validation → risk LOW → atomic transfer → audit. Sign in as Sara to show the credit and her history.
3. **Security → Add a passkey** (Windows Hello, or Chrome DevTools → WebAuthn → virtual authenticator).
4. **Send Rs 75,000 to Hina** → passkey prompt. Trace: challenge = SHA-256(nonce ‖ transfer) → clientDataJSON → byte map → ECDSA verify → checklist.
5. **Security Lab.** For each card: switch the control off → *Run attack* (Before) → switch it on → *Run attack* (After).
   - W1: switch the API filter off first and show RLS still blocks it; then switch both off.
   - W3 and W8: explain the attacker model.
6. **Sign in as `auditor`** → reconciliation (shows the W7 mismatch if the race was run) → the audit trail, with the rejections and Lab switches.
7. **Reset demo data** in the Lab when done.

---

## 7. Limitations / future work

- **No TLS in the local stack.** Production terminates TLS 1.3 at nginx (WebAuthn allows `localhost` over HTTP).
- **Signing key storage.** The key sits in a Docker volume rather than a KMS/HSM.
- **Single-instance state.** The IP rate limiter is in memory; production would use Redis behind multiple API instances.
- **Seeded funding only.** There is no top-up/bank integration, so money enters only through seeded treasury deposits.
- **Rule-based risk engine.** It covers amount and new payee only; velocity and device signals are future work.
- **Lab reset truncates the audit log.** This is an intentional, demo-only owner action.

---

### W11 Transaction PIN

| | |
|---|---|
| **Brief's question** | Can unauthorized users perform sensitive operations? |
| **Asset** | Wallet balance |
| **Weakness** | A stolen access token, or a session left open on a shared device, is enough to send money. |
| **Impact** | Money is sent without the account holder knowing (I). |
| **Control** | A 6-digit transaction PIN is required in the body (`tpin`) of every `POST /api/transfers`. It is stored as an argon2id hash with the same profile as passwords, and setting it requires the account password again. Weak PINs are refused: one repeated digit, ascending or descending runs, and a list of common PINs. Three wrong PINs lock transfers for 15 minutes, and the right PIN is refused while the lock is on. The PIN is checked before the risk engine, so passkey step-up transfers also need it; `/confirm` does not ask again. It is excluded from the idempotency request hash and never written to the audit log or the trace. |
| **Where** | `security/tpin.py` (hash, verify, weak-PIN rules), `routers/tpin.py` (`POST /api/tpin`, `enforce()`), `routers/transfers.py` (check before idempotency), `users.tpin_*` columns, `Security.jsx` / `Send.jsx` |
| **API** | `POST /api/tpin {password, new_pin}`: 200, wrong password 403 (counts toward the login lockout), weak 422. On a transfer: `403 tpin_required` (no PIN set), `403 tpin_missing`, `403 tpin_wrong` ("N attempts left"), `423 tpin_locked` with `Retry-After` |
| **Result (test)** | `tests/test_tpin.py`. Before (lab `tpin` off): a transfer with no PIN returns 201. After: 403. Three wrong PINs return 403, 403, 423, and the right PIN then also gets 423. A new account gets 403 `tpin_required`. Seeded customers' PIN is `482915`. |
| **Limitation** | A 6-digit PIN has only 10⁶ values, so a leaked hash could be brute-forced offline in hours despite argon2id. The real control is the online 3-strike lock, and the PIN is a second factor on top of the session, not a replacement for the password. |

### W12 Encryption at rest

| | |
|---|---|
| **Brief's question** | Can credentials or customer information be exposed? |
| **Asset** | Customers' full names, transfer notes, audit details (and the replay copies of transfer responses) |
| **Weakness** | Sensitive columns are stored as plaintext, so a database dump, a stolen backup or a curious DBA reads them directly, without going through the API, RLS or RBAC. |
| **Impact** | Privacy breach of every customer at once (C). |
| **Control** | App-level authenticated encryption with **AES-256-GCM** (`cryptography`'s `AESGCM`). A 32-byte data key is created on first start in the keys volume (`/keys/data_key_v1`, mode 0600), next to the JWT key and never in the database. Each value is stored as the text `enc:v1:<base64url(nonce ‖ ciphertext ‖ tag)>`: `v1` is the key id (so a key can be rotated later), and each value gets a random 96-bit nonce. The **AAD binds every ciphertext to its location**, so a value pasted into another row or column fails its tag check: `users.full_name:<user id>`, `transactions.note:<sender id>`, `pending_transfers.note:<user id>`, `idempotency_keys.response:<user id>:<key>`, and `audit_log.detail` (column only: the row id comes from the sequence at INSERT, after encryption). Rows that don't start with `enc:` pass through, so old or lab-plaintext rows still read. A value whose tag fails is shown as `[unreadable]` instead of an error. The passkey challenge is built from the **plaintext** note at both ends, so it is unchanged by encryption. |
| **Where** | `security/crypto.py` (key, `encrypt`/`decrypt`/`reveal`, trace steps), `main.py` (key load before migrate), `routers/auth.py` (register: id generated in Python, name encrypted), `routers/transfers.py` (notes, replay copies), `routers/wallet.py`, `routers/auditing.py`, `routers/passkeys.py`, `audit.py` (detail stored as `{"enc": "…"}`), `migrate.py` (seed data encrypted), lab endpoints `/api/lab/users-table` and `/api/lab/raw-transactions` (values exactly as stored) |
| **Not encrypted, on purpose** | **Balances and amounts** stay plaintext `BIGINT`: `transfer_funds()` locks, checks (`balance >= 0`) and updates them inside one SQL transaction, and `reconcile_ledger()` sums them. Encrypting them would move that arithmetic into the app and lose the database-enforced integrity of W5/W7. **Usernames** stay plaintext because they are the login and lookup key (a deterministic encryption or blind index would be needed to search them). Password and PIN hashes are already one-way (W2, W11). |
| **Result (test)** | `tests/test_encryption.py`. Unit: round trip, a fresh nonce per value, wrong AAD fails, one flipped bit fails, unknown key id fails, plaintext passes through. End to end: a new user's `full_name` is `enc:v1:…` in the users table while `/api/me` shows the name as typed; a transfer note is `enc:v1:…` in the transactions table and plaintext in both parties' history; the auditor sees decrypted details. Before (lab `encryption_at_rest` off): new names and notes are stored as typed. After: ciphertext. Mixed rows read correctly. |
| **Limitation** | The key sits in a Docker volume on the same host as the API, so this protects dumps, backups and DB-only access, not a compromise of the API host itself. Production would use **envelope encryption** with a KMS/HSM: the KMS holds a key-encryption key that never leaves it and unwraps the data key at start-up, with audited access and scheduled rotation (new rows under `v2`, old rows re-encrypted in the background). The `audit_log.detail` AAD cannot include the row id. Ciphertext grows a value by 28 bytes plus base64: the 600-character column limit fits up to 416 bytes of UTF-8, which covers every 140-character note in English or Urdu, but a note of 139+ CJK characters or many emoji would exceed it and be refused by the CHECK. |

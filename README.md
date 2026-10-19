# SecureWallet

A mini secure fintech wallet. You can create an account, sign in, check your balance, send money to another customer, view your history and sign out.
Security design and the Asset → Weakness → Impact → Control analysis are in [SPEC.md](SPEC.md).

## Run

Requires Docker Desktop.

```bash
cp .env.example .env        # then change the three passwords
docker compose up --build
```

Open **http://localhost:8080**. Use `localhost`, not `127.0.0.1`: passkeys are bound to that name.

Demo accounts (password `Wallet@2026!`):

| User | Role |
|---|---|
| `ali`, `sara`, `bilal`, `hina` | customers with seeded balances and history |
| `auditor` | audit desk (audit log, reconciliation), cannot move money |

## Presenter tools (for the demo)

With `DEMO_MODE=true` (the default in `.env.example`), open the avatar menu → **Presenter tools**, or press **Ctrl+Shift+D**. This adds:

- **Security trace:** a drawer showing every security check the server ran for each request, with real values and the math (ECDSA verification, argon2id, RLS, FIDO2 byte maps).
- **Security lab:** switch each control off, run its attack (before), switch it back on and run it again (after).

Set `DEMO_MODE=false` and both disappear completely: the endpoints are not mounted and trace data is never collected.

**Passkeys without Windows Hello:** in Chrome open DevTools → ⋮ → More tools → **WebAuthn** → *Enable virtual authenticator environment* → add an `internal` authenticator with user verification.

## Tests

With the app running (`docker compose up`, `DEMO_MODE=true`), run the whole suite inside Docker from this folder. Nothing needs installing on the host:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml run --rm tests
```

46 end-to-end tests, about 2 minutes: the brief's functional flow (Ali → Rs 2,000 → Sara), a before/after test for every control W1–W13, a full passkey step-up with a software FIDO2 authenticator, transaction-PIN and beneficiary rules, encryption-at-rest unit tests and the inactivity timeout. The tests reset the demo data, so sign in again afterwards.

## Report

`report/main.tex` (figures in `report/figures/`) builds to `report/main.pdf`:

```bash
cd report
pdflatex main.tex && pdflatex main.tex     # or: tectonic main.tex, or upload the folder to Overleaf
```

## Layout

```
db/init/01-roles.sh          DB roles: wallet_owner (schema) and wallet_app (API, bound by RLS)
backend/app/sql/schema.sql   tables, RLS policies, grants, transfer_funds(), reconcile_ledger()
backend/app/                 FastAPI app (routers/, security/, trace.py, lab.py, audit.py)
backend/tests/               end-to-end security tests
frontend/src/                React app (pages/, components/, api.js, trace.js)
frontend/nginx.conf          CSP, security headers, rate limits, /api proxy
```

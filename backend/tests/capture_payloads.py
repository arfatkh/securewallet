"""Capture real request/response payloads from the running stack for the presentation guide.

    python -m tests.capture_payloads <out.json>      (run from backend/, stack on localhost:8000)
"""
import base64
import json
import sys
import time
import uuid

import httpx

from .softauthn import SoftAuthenticator

BASE = "http://localhost:8000"
PW, PIN = "Wallet@2026!", "482915"
out = []


def short(v, n=48):
    if isinstance(v, str) and len(v) > n:
        return v[:n // 2] + "…" + v[-12:]
    if isinstance(v, dict):
        return {k: short(x, n) for k, x in v.items()}
    if isinstance(v, list):
        return [short(x, n) for x in v[:6]] + (["…"] if len(v) > 6 else [])
    return v


def rec(name, method, path, req_body, r, req_headers=None, note=""):
    try:
        body = r.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        body.pop("_trace", None)
    hdrs = {k: v for k, v in r.headers.items() if k.lower() in ("set-cookie", "retry-after", "idempotent-replayed")}
    if "set-cookie" in hdrs:
        hdrs["set-cookie"] = "sw_refresh=<random 256-bit token>; " + "; ".join(
            p.strip() for p in hdrs["set-cookie"].split(";")[1:])
    out.append({"name": name, "method": method, "path": path, "req_headers": req_headers or {},
                "req_body": short(req_body) if req_body is not None else None,
                "status": r.status_code, "resp_headers": hdrs, "resp_body": short(body), "note": note})


def client(token=None):
    h = {"X-Requested-With": "securewallet"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=BASE, timeout=30, headers=h)


def login(u):
    c = client()
    r = c.post("/api/auth/login", json={"username": u, "password": PW})
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return c, r


admin, _ = login("ali")
admin.post("/api/lab/reset")

# ---- sign in
c = client()
body = {"username": "ali", "password": "Wallet@2026!"}
r = c.post("/api/auth/login", json=body)
rec("login", "POST", "/api/auth/login", {"username": "ali", "password": "••••••••••••"}, r)
tok = r.json()["access_token"]
c.headers["Authorization"] = f"Bearer {tok}"
h, p, s = tok.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
out.append({"name": "jwt_decoded", "header": json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))),
            "claims": claims})

rec("me", "GET", "/api/me", None, c.get("/api/me"))
rec("lookup", "GET", "/api/users/lookup?username=sara", None, c.get("/api/users/lookup?username=sara"))

# ---- transfer + replay
key = str(uuid.uuid4())
tb = {"to_username": "sara", "amount": 200000, "note": "Rent share", "tpin": PIN}
r = c.post("/api/transfers", json=tb, headers={"Idempotency-Key": key})
rec("transfer_ok", "POST", "/api/transfers", {**tb, "tpin": "••••••"}, r, {"Idempotency-Key": key})
r = c.post("/api/transfers", json=tb, headers={"Idempotency-Key": key})
rec("transfer_replay", "POST", "/api/transfers", {**tb, "tpin": "••••••"}, r, {"Idempotency-Key": key},
    "same key, same body, sent again")
r = c.post("/api/transfers", json={**tb, "amount": 999}, headers={"Idempotency-Key": key})
rec("transfer_key_conflict", "POST", "/api/transfers", {**tb, "amount": 999, "tpin": "••••••"}, r, {"Idempotency-Key": key})

# ---- PIN errors (on bilal so ali is not locked)
b, _ = login("bilal")
r = b.post("/api/transfers", json={"to_username": "hina", "amount": 100000}, headers={"Idempotency-Key": str(uuid.uuid4())})
rec("pin_missing", "POST", "/api/transfers", {"to_username": "hina", "amount": 100000}, r)
r = b.post("/api/transfers", json={"to_username": "hina", "amount": 100000, "tpin": "111222"},
           headers={"Idempotency-Key": str(uuid.uuid4())})
rec("pin_wrong", "POST", "/api/transfers", {"to_username": "hina", "amount": 100000, "tpin": "111222"}, r)
for _ in range(2):
    r = b.post("/api/transfers", json={"to_username": "hina", "amount": 100000, "tpin": "111222"},
               headers={"Idempotency-Key": str(uuid.uuid4())})
rec("pin_locked_after_3", "POST", "/api/transfers", {"to_username": "hina", "amount": 100000, "tpin": "111222"}, r,
    note="third wrong PIN in a row")

# ---- validation
r = c.post("/api/transfers", json={"to_username": "sara", "amount": -500000, "tpin": PIN},
           headers={"Idempotency-Key": str(uuid.uuid4())})
rec("negative_amount", "POST", "/api/transfers", {"to_username": "sara", "amount": -500000, "tpin": "••••••"}, r)
r = c.post("/api/transfers", json={"to_username": "sara", "amount": 1.5, "tpin": PIN},
           headers={"Idempotency-Key": str(uuid.uuid4())})
rec("float_amount", "POST", "/api/transfers", {"to_username": "sara", "amount": 1.5, "tpin": "••••••"}, r)
r = c.post("/api/transfers", json={"to_username": "sara", "amount": 100, "tpin": PIN, "balance": 10**9},
           headers={"Idempotency-Key": str(uuid.uuid4())})
rec("mass_assignment", "POST", "/api/transfers", {"to_username": "sara", "amount": 100, "tpin": "••••••", "balance": 10**9}, r)

# ---- BOLA
sara = next(t for t in c.get("/api/lab/targets").json()["items"] if t["username"] == "sara")
rec("bola", "GET", "/api/wallets/{sara's wallet id}", None, c.get(f"/api/wallets/{sara['wallet_id']}"))

# ---- forged token
pl = dict(claims, sub=sara["user_id"], name="sara")
forged = f"{h}.{base64.urlsafe_b64encode(json.dumps(pl).encode()).rstrip(b'=').decode()}.{s}"
rec("forged_token", "GET", "/api/me", None, client(forged).get("/api/me"),
    {"Authorization": "Bearer <ali's token with sub changed to sara, old signature>"})

# ---- passkey + step-up
dev = SoftAuthenticator()
r = c.post("/api/passkeys/register/options")
opts = r.json()
rec("passkey_options", "POST", "/api/passkeys/register/options", None, r)
cred = dev.register(opts)
r = c.post("/api/passkeys/register/verify", json={"credential": cred, "nickname": "Windows Hello"})
rec("passkey_verify", "POST", "/api/passkeys/register/verify", {"credential": short(cred), "nickname": "Windows Hello"}, r)
key2 = str(uuid.uuid4())
r = c.post("/api/transfers", json={"to_username": "hina", "amount": 7500000, "tpin": PIN}, headers={"Idempotency-Key": key2})
pend = r.json()
rec("stepup_202", "POST", "/api/transfers", {"to_username": "hina", "amount": 7500000, "tpin": "••••••"}, r, {"Idempotency-Key": key2})
assertion = dev.assert_(pend["options"])
r = c.post(f"/api/transfers/{pend['pending_id']}/confirm", json={"credential": assertion})
rec("stepup_confirm", "POST", "/api/transfers/{pending_id}/confirm", {"credential": short(assertion)}, r)
r = c.post(f"/api/transfers/{pend['pending_id']}/confirm", json={"credential": dev.assert_(pend["options"])})
rec("stepup_replay", "POST", "/api/transfers/{pending_id}/confirm", {"credential": "<a second, valid assertion>"}, r)

# ---- roles
rec("customer_audit", "GET", "/api/audit", None, c.get("/api/audit"))
aud, _ = login("auditor")
r = aud.get("/api/audit/reconcile")
rec("reconcile", "GET", "/api/audit/reconcile", None, r)
r = aud.get("/api/audit?limit=3")
rec("audit_rows", "GET", "/api/audit?limit=3", None, r)

# ---- encryption at rest
rec("db_users_raw", "GET", "/api/lab/users-table", None, c.get("/api/lab/users-table"),
    note="values exactly as stored in PostgreSQL")
rec("db_tx_raw", "GET", "/api/lab/raw-transactions", None, c.get("/api/lab/raw-transactions"),
    note="values exactly as stored in PostgreSQL")

# ---- trace step titles for one transfer
r = c.post("/api/transfers", json={"to_username": "sara", "amount": 50000, "tpin": PIN},
           headers={"Idempotency-Key": str(uuid.uuid4()), "X-Security-Trace": "1"})
out.append({"name": "trace_transfer", "steps": [{"lane": st["lane"], "layer": st["layer"], "title": st["title"],
                                                 "status": st["status"]} for st in r.json()["_trace"]]})

# ---- brute force
g = client()
codes = [g.post("/api/auth/login", json={"username": "hina", "password": f"guess{i}"}) for i in range(6)]
rec("login_wrong", "POST", "/api/auth/login", {"username": "hina", "password": "guess0"}, codes[0])
rec("login_locked", "POST", "/api/auth/login", {"username": "hina", "password": "guess5"}, codes[5], note="6th attempt")

# ---- idle timeout (15 s demo limit)
admin2, _ = login("sara")
admin2.put("/api/lab/settings/session_idle_seconds", json={"value": "15"})
sr, _ = login("sara")
time.sleep(17)
rec("idle_401", "GET", "/api/me", None, sr.get("/api/me"), note="after 17 s with no activity, 15 s demo limit")
admin3, _ = login("bilal")
admin3.put("/api/lab/settings/session_idle_seconds", json={"value": "300"})
admin3.post("/api/lab/reset")

json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=1, ensure_ascii=False, default=str)
print("captured", len(out))

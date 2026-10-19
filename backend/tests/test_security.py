"""End-to-end tests against a running stack (DEMO_MODE=true).

    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d db api
    pytest backend/tests -v

Each weakness is tested twice: with the control switched off (the attack
works: "before") and on (the attack is blocked: "after").
"""
import base64
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from .softauthn import SoftAuthenticator

BASE = os.getenv("API_URL", "http://localhost:8000")
PW = "Wallet@2026!"


def client() -> httpx.Client:
    return httpx.Client(base_url=BASE, timeout=30, headers={"X-Requested-With": "securewallet"})


def login(username: str, password: str = PW) -> tuple[httpx.Client, dict]:
    c = client()
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return c, r.json()


def balance(c: httpx.Client) -> int:
    return c.get("/api/me").json()["wallet"]["balance"]


TPIN = "482915"  # seeded transaction PIN (W11)


def send(c: httpx.Client, to: str, amount, key: str | None = None, tpin: str | None = TPIN,
         **extra) -> httpx.Response:
    """tpin=None leaves the PIN out of the body entirely."""
    body = {"to_username": to, "amount": amount, **extra}
    if tpin is not None:
        body["tpin"] = tpin
    return c.post("/api/transfers", json=body, headers={"Idempotency-Key": key or str(uuid.uuid4())})


def flag(c: httpx.Client, name: str, enabled: bool) -> None:
    assert c.put(f"/api/lab/flags/{name}", json={"enabled": enabled}).status_code == 200


@pytest.fixture(autouse=True)
def fresh_data():
    c, _ = login("ali")
    assert c.post("/api/lab/reset").status_code == 200
    yield


# ------------------------------------------------------------------ functional
def test_brief_example_ali_sends_sara_2000():
    ali, _ = login("ali")
    sara, _ = login("sara")
    a0, s0 = balance(ali), balance(sara)
    r = send(ali, "sara", 200000, note="Ali → Rs 2,000 → Sara")
    assert r.status_code == 201 and r.json()["status"] == "completed"
    assert balance(ali) == a0 - 200000 and balance(sara) == s0 + 200000
    ref = r.json()["ref"]
    assert any(t["ref"] == ref and t["direction"] == "sent" for t in ali.get("/api/transactions").json()["items"])
    tx = next(t for t in sara.get("/api/transactions").json()["items"] if t["ref"] == ref)
    assert tx["direction"] == "received" and tx["counterparty"]["username"] == "ali"
    assert {"created_at", "status", "amount"} <= tx.keys()


def test_insufficient_funds_is_recorded_as_failed():
    bilal, _ = login("bilal")
    r = send(bilal, "hina", balance(bilal) + 1)
    assert r.status_code == 422 and r.json()["reason"] == "insufficient funds"
    assert bilal.get("/api/transactions").json()["items"][0]["status"] == "failed"


def test_logout_revokes_the_access_token():
    ali, _ = login("ali")
    assert ali.post("/api/auth/logout", json={}).status_code == 200
    assert ali.get("/api/me").status_code == 401


def test_register_then_login():
    c = client()
    r = c.post("/api/auth/register", json={"username": "zara_01", "full_name": "Zara Iqbal",
                                           "password": "blue-kite-harbor-7"})
    assert r.status_code == 201
    assert c.post("/api/auth/register", json={"username": "ZARA_01", "full_name": "Z",
                                              "password": "blue-kite-harbor-7"}).status_code in (409, 422)
    login("zara_01", "blue-kite-harbor-7")


def test_refresh_rotation_and_reuse_detection():
    c = client()
    assert c.post("/api/auth/login", json={"username": "ali", "password": PW}).status_code == 200
    old = c.cookies.get("sw_refresh")
    assert c.post("/api/auth/refresh").status_code == 200
    thief = client()
    thief.cookies.set("sw_refresh", old, path="/api/auth")
    assert thief.post("/api/auth/refresh").status_code == 401       # rotated token replayed
    assert c.post("/api/auth/refresh").status_code == 401           # whole family revoked


# ------------------------------------------------------------------ W1 BOLA / RLS
def test_W1_bola_two_layers():
    ali, _ = login("ali")
    target = next(t for t in ali.get("/api/lab/targets").json()["items"] if t["username"] == "sara")
    url = f"/api/wallets/{target['wallet_id']}"
    assert ali.get(url).status_code == 404                           # after: both layers on
    flag(ali, "ownership_check", False)
    assert ali.get(url).status_code == 404                           # RLS alone still blocks it
    flag(ali, "rls", False)
    r = ali.get(url)
    assert r.status_code == 200 and r.json()["owner"]["username"] == "sara"   # before: leaked
    assert any(t.get("leaked") for t in ali.get("/api/transactions?limit=50").json()["items"])
    flag(ali, "rls", True)
    assert ali.get(url).status_code == 404


# ------------------------------------------------------------------ W2 password storage
def test_W2_password_hashing():
    ali, _ = login("ali")
    flag(ali, "argon2", False)
    client().post("/api/auth/register", json={"username": "plain_pat", "full_name": "Plain Pat",
                                              "password": "open-sesame-2026"})
    flag(ali, "argon2", True)
    client().post("/api/auth/register", json={"username": "hashed_hal", "full_name": "Hashed Hal",
                                              "password": "open-sesame-2026"})
    rows = {r["username"]: r["password_hash"] for r in ali.get("/api/lab/users-table").json()["items"]}
    assert rows["plain_pat"] == "plain$open-sesame-2026"
    assert rows["hashed_hal"].startswith("$argon2id$v=19$m=65536,t=3,p=2$")


# ------------------------------------------------------------------ W3 brute force
def test_W3_lockout_blocks_guessing():
    c = client()
    codes = [c.post("/api/auth/login", json={"username": "sara", "password": f"guess{i}"}).status_code
             for i in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert c.post("/api/auth/login", json={"username": "sara", "password": PW}).status_code == 429


def test_W3_without_throttle_the_password_is_found():
    ali, _ = login("ali")
    flag(ali, "login_throttle", False)
    c = client()
    for i in range(10):
        assert c.post("/api/auth/login", json={"username": "sara", "password": f"guess{i}"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "sara", "password": PW}).status_code == 200


# ------------------------------------------------------------------ W4 token forgery
def _forge(token: str, **changes) -> str:
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    payload.update(changes)
    p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p2}.{s}"


def test_W4_forged_token():
    ali, body = login("ali")
    sara_id = next(t for t in ali.get("/api/lab/targets").json()["items"] if t["username"] == "sara")["user_id"]
    forged = _forge(body["access_token"], sub=sara_id, name="sara")
    evil = client()
    evil.headers["Authorization"] = f"Bearer {forged}"
    assert evil.get("/api/me").status_code == 401                    # after
    flag(ali, "jwt_verification", False)
    r = evil.get("/api/me")
    assert r.status_code == 200 and r.json()["user"]["username"] == "sara"   # before
    flag(ali, "jwt_verification", True)
    none_alg = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + forged.split(".")[1] + "."
    evil.headers["Authorization"] = f"Bearer {none_alg}"
    assert evil.get("/api/me").status_code == 401


# ------------------------------------------------------------------ W5 input validation
def test_W5_invalid_amounts_rejected():
    ali, _ = login("ali")
    for bad in (0, -500000, 50_000_001):
        assert send(ali, "sara", bad).status_code == 422
    assert send(ali, "sara", 1.5).status_code == 422
    assert send(ali, "sara", "100").status_code == 422
    assert send(ali, "sara", 100, balance=10**9).status_code == 422   # mass assignment
    assert send(ali, "ali", 100).status_code == 422                   # self-transfer
    assert send(ali, "nobody_here", 100).status_code == 404


def test_W5_negative_amount_without_validation_steals_money():
    ali, _ = login("ali")
    before = balance(ali)
    flag(ali, "amount_validation", False)
    r = send(ali, "sara", -500000)
    assert r.status_code == 201
    assert balance(ali) == before + 500000                           # before: ali gained Rs 5,000
    flag(ali, "amount_validation", True)
    assert send(ali, "sara", -500000).status_code == 422


# ------------------------------------------------------------------ W6 replay / double submit
def _burst(c, n, to, amount, key=None):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(lambda _: send(c, to, amount, key=key), range(n)))


def test_W6_idempotency():
    ali, _ = login("ali")
    before = balance(ali)
    key = str(uuid.uuid4())
    rs = _burst(ali, 5, "sara", 100000, key)
    assert {r.status_code for r in rs} == {201}
    assert balance(ali) == before - 100000                           # after: paid once
    assert len({r.json()["ref"] for r in rs}) == 1
    assert ali.post("/api/transfers", json={"to_username": "sara", "amount": 999, "tpin": TPIN},
                    headers={"Idempotency-Key": key}).status_code == 409
    flag(ali, "idempotency", False)
    before = balance(ali)
    _burst(ali, 5, "sara", 100000, str(uuid.uuid4()))
    assert balance(ali) < before - 100000                            # before: paid more than once


# ------------------------------------------------------------------ W7 race / atomicity
def test_W7_parallel_transfers_are_consistent():
    ali, _ = login("ali")
    auditor, _ = login("auditor")
    before = balance(ali)
    rs = _burst(ali, 10, "sara", 100000)
    assert all(r.status_code == 201 for r in rs)
    assert balance(ali) == before - 10 * 100000                       # after: every debit applied
    assert auditor.get("/api/audit/reconcile").json()["ok"] is True
    flag(ali, "row_locking", False)
    before = balance(ali)
    _burst(ali, 10, "sara", 100000)
    assert balance(ali) > before - 10 * 100000                        # before: lost updates
    assert auditor.get("/api/audit/reconcile").json()["ok"] is False  # and the ledger no longer adds up


# ------------------------------------------------------------------ W8 step-up with FIDO2
def test_W8_large_transfer_needs_passkey():
    ali, _ = login("ali")
    assert send(ali, "sara", 6_000_000).status_code == 403           # no passkey yet
    flag(ali, "step_up", False)
    assert send(ali, "sara", 6_000_000).status_code == 201           # before: a stolen session is enough
    flag(ali, "step_up", True)


def test_W8_passkey_step_up_end_to_end():
    ali, _ = login("ali")
    dev = SoftAuthenticator()
    opts = ali.post("/api/passkeys/register/options").json()
    assert ali.post("/api/passkeys/register/verify",
                    json={"credential": dev.register(opts), "nickname": "Test key"}).status_code == 201
    before = balance(ali)
    r = send(ali, "hina", 7_500_000)
    assert r.status_code == 202
    pending = r.json()
    assert balance(ali) == before                                     # nothing moved yet
    # wrong origin (phishing site) and wrong challenge are both refused
    bad = ali.post(f"/api/transfers/{pending['pending_id']}/confirm",
                   json={"credential": dev.assert_(pending["options"], origin="http://evil.example")})
    assert bad.status_code == 400
    bad = ali.post(f"/api/transfers/{pending['pending_id']}/confirm",
                   json={"credential": dev.assert_(pending["options"], tamper_challenge=True)})
    assert bad.status_code == 400
    ok = ali.post(f"/api/transfers/{pending['pending_id']}/confirm",
                  json={"credential": dev.assert_(pending["options"])})
    assert ok.status_code == 201, ok.text
    assert balance(ali) == before - 7_500_000
    replay = ali.post(f"/api/transfers/{pending['pending_id']}/confirm",
                      json={"credential": dev.assert_(pending["options"])})
    assert replay.status_code == 409                                 # single use


# ------------------------------------------------------------------ W9 privilege separation
def test_W9_audit_is_auditor_only():
    ali, _ = login("ali")
    auditor, _ = login("auditor")
    assert ali.get("/api/audit").status_code == 403
    assert auditor.get("/api/audit").status_code == 200
    assert auditor.post("/api/transfers", json={"to_username": "sara", "amount": 100},
                        headers={"Idempotency-Key": str(uuid.uuid4())}).status_code == 403
    flag(ali, "rbac", False)
    assert ali.get("/api/audit").status_code == 200                  # before: a customer reads the audit log
    assert ali.get("/api/audit/reconcile").status_code == 403         # the DB function still refuses


# ------------------------------------------------------------------ W10 accountability
def test_W10_rejections_are_audited_without_secrets():
    c = client()
    c.post("/api/auth/login", json={"username": "sara", "password": "not-her-password"})
    auditor, _ = login("auditor")
    items = auditor.get("/api/audit?action=auth.login").json()["items"]
    failed = next(i for i in items if i["outcome"] == "failed")
    assert "not-her-password" not in json.dumps(items)
    assert failed["detail"]["username"] == "sara"


# ------------------------------------------------------------------ trace
def test_trace_only_when_requested():
    ali, _ = login("ali")
    assert "_trace" not in ali.get("/api/me").json()
    traced = ali.get("/api/me", headers={"X-Security-Trace": "1"}).json()
    titles = [s["title"] for s in traced["_trace"]]
    assert any("Verify ES256 signature" in t for t in titles)
    sig = next(s for s in traced["_trace"] if "Verify ES256" in s["title"])
    assert sig["status"] == "pass" and sig["math"][-1].endswith("✓ signature valid")

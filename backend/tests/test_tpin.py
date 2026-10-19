"""W11: transaction PIN. Runs against the same stack as test_security.py (DEMO_MODE=true)."""
from .test_security import PW, TPIN, balance, client, flag, fresh_data, login, send  # noqa: F401 (autouse fixture)


def _new_customer(username: str, password: str = "blue-kite-harbor-7"):
    c = client()
    r = c.post("/api/auth/register", json={"username": username, "full_name": "Pin Tester", "password": password})
    assert r.status_code == 201, r.text
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return c


def test_W11_new_user_must_set_a_pin_first():
    c = _new_customer("pin_new")
    assert c.get("/api/me").json()["has_tpin"] is False
    r = send(c, "sara", 100, tpin="482915")
    assert r.status_code == 403 and r.json()["code"] == "tpin_required"


def test_W11_set_pin_reauth_and_policy():
    c = _new_customer("pin_set")
    r = c.post("/api/tpin", json={"password": "wrong-password-1", "new_pin": "482915"})
    assert r.status_code == 403                                       # wrong password
    for weak in ("111111", "123456", "654321", "123123", "121212"):
        assert c.post("/api/tpin", json={"password": "blue-kite-harbor-7", "new_pin": weak}).status_code == 422
    assert c.post("/api/tpin", json={"password": "blue-kite-harbor-7", "new_pin": "12ab56"}).status_code == 422
    assert c.post("/api/tpin", json={"password": "blue-kite-harbor-7", "new_pin": "730518"}).status_code == 200
    assert c.get("/api/me").json()["has_tpin"] is True
    r = send(c, "sara", 100, tpin="730518")                         # PIN accepted; the empty wallet then fails
    assert r.status_code == 422 and r.json()["reason"] == "insufficient funds"


def test_W11_correct_pin_sends():
    ali, _ = login("ali")
    before = balance(ali)
    assert send(ali, "sara", 100000).status_code == 201
    assert balance(ali) == before - 100000


def test_W11_missing_or_wrong_pin_then_lock():
    ali, _ = login("ali")
    before = balance(ali)
    r = send(ali, "sara", 100000, tpin=None)
    assert r.status_code == 403 and r.json()["code"] == "tpin_missing"
    r = send(ali, "sara", 100000, tpin="000001")
    assert r.status_code == 403 and r.json()["code"] == "tpin_wrong" and "2 attempts left" in r.json()["detail"]
    r = send(ali, "sara", 100000, tpin="000002")
    assert r.status_code == 403 and "1 attempt left" in r.json()["detail"]
    r = send(ali, "sara", 100000, tpin="000003")
    assert r.status_code == 423 and r.json()["code"] == "tpin_locked"
    assert send(ali, "sara", 100000).status_code == 423                # even the right PIN while locked
    assert balance(ali) == before                                     # nothing moved


def test_W11_success_resets_the_counter():
    ali, _ = login("ali")
    assert send(ali, "sara", 100, tpin="000001").status_code == 403
    assert send(ali, "sara", 100, tpin="000002").status_code == 403
    assert send(ali, "sara", 100).status_code == 201
    r = send(ali, "sara", 100, tpin="000003")
    assert r.status_code == 403 and "2 attempts left" in r.json()["detail"]


def test_W11_stolen_session_without_pin():
    ali, _ = login("ali")
    before = balance(ali)
    flag(ali, "tpin", False)
    assert send(ali, "sara", 100000, tpin=None).status_code == 201     # before: the token alone moves money
    assert balance(ali) == before - 100000
    flag(ali, "tpin", True)
    assert send(ali, "sara", 100000, tpin=None).status_code == 403     # after
    assert balance(ali) == before - 100000


def test_W11_pin_is_not_stored_in_audit():
    ali, _ = login("ali")
    send(ali, "sara", 100, tpin="000009")
    auditor, _ = login("auditor")
    items = auditor.get("/api/audit?action=transfer.create").json()["items"]
    assert any(i["outcome"] == "tpin_wrong" for i in items)
    text = str(items)
    assert "000009" not in text and TPIN not in text
    assert PW not in text

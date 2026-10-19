"""Saved payees (beneficiaries): adding one needs the transaction PIN (W11)."""
from .test_security import TPIN, flag, fresh_data, login  # noqa: F401  (fresh_data: autouse reset)


def add(c, username, tpin=TPIN, **extra):
    body = {"username": username, **extra}
    if tpin is not None:
        body["tpin"] = tpin
    return c.post("/api/beneficiaries", json=body)


def test_seeded_beneficiaries_are_listed():
    ali, _ = login("ali")
    items = ali.get("/api/beneficiaries").json()["items"]
    assert {b["username"] for b in items} == {"sara", "hina"}
    assert next(b for b in items if b["username"] == "sara")["nickname"] == "Sara - rent"


def test_adding_needs_the_pin():
    ali, _ = login("ali")
    r = add(ali, "bilal", tpin=None)
    assert r.status_code == 403 and r.json()["code"] == "tpin_missing"
    r = add(ali, "bilal", tpin="111222")
    assert r.status_code == 403 and r.json()["code"] == "tpin_wrong"
    r = add(ali, "bilal", nickname="Cricket team")
    assert r.status_code == 201 and r.json()["nickname"] == "Cricket team"
    assert "bilal" in {b["username"] for b in ali.get("/api/beneficiaries").json()["items"]}


def test_wrong_pins_share_the_transfer_lock():
    bilal, _ = login("bilal")
    for _ in range(2):
        assert add(bilal, "sara", tpin="111222").status_code == 403
    r = add(bilal, "sara", tpin="111222")
    assert r.status_code == 423 and r.json()["code"] == "tpin_locked"
    # the same lock now also blocks transfers, even with the right PIN
    r = bilal.post("/api/transfers", json={"to_username": "sara", "amount": 1000, "tpin": TPIN},
                   headers={"Idempotency-Key": "lock-check-0001"})
    assert r.status_code == 423


def test_validation():
    ali, _ = login("ali")
    assert add(ali, "nobody_here").status_code == 404
    assert add(ali, "ali").status_code == 422
    assert add(ali, "sara").status_code == 409                          # already saved
    assert add(ali, "bilal", nickname="x" * 41).status_code == 422
    assert ali.post("/api/beneficiaries", json={"username": "bilal", "tpin": TPIN, "user_id": "x"}).status_code == 422


def test_each_customer_sees_only_their_own():
    ali, _ = login("ali")
    sara, _ = login("sara")
    assert sara.get("/api/beneficiaries").json()["items"] == []        # RLS: Ali's rows are invisible
    ali_entry = ali.get("/api/beneficiaries").json()["items"][0]
    assert sara.delete(f"/api/beneficiaries/{ali_entry['id']}").status_code == 404
    assert ali.delete(f"/api/beneficiaries/{ali_entry['id']}").status_code == 200
    assert ali_entry["id"] not in {b["id"] for b in ali.get("/api/beneficiaries").json()["items"]}


def test_without_the_pin_control_anyone_with_the_session_can_add():
    ali, _ = login("ali")
    flag(ali, "tpin", False)
    assert add(ali, "bilal", tpin=None).status_code == 201             # before: session alone adds a payee
    flag(ali, "tpin", True)
    r = add(ali, "hina", tpin=None)                                     # after: refused before anything else
    assert r.status_code == 403 and r.json()["code"] == "tpin_missing"


def test_auditor_cannot_manage_beneficiaries():
    aud, _ = login("auditor")
    assert aud.get("/api/beneficiaries").status_code == 403

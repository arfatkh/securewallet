"""W12: encryption at rest.

The unit tests exercise security/crypto.py directly (no stack needed). The
end-to-end tests run against the same stack as test_security.py (DEMO_MODE=true)
and read the tables through the lab's owner connection, as a DBA or a stolen
backup would.
"""
import types
import uuid

import pytest

from .test_security import TPIN, client, flag, login, send


# ------------------------------------------------------------------ unit: crypto.py
@pytest.fixture
def crypto(tmp_path, monkeypatch):
    pytest.importorskip("psycopg_pool")  # crypto imports the app's lab module, which imports the DB pool
    from app.security import crypto as mod
    monkeypatch.setattr(mod, "settings", types.SimpleNamespace(keys_dir=str(tmp_path)))
    monkeypatch.setattr(mod, "_keys", {})
    mod.load_or_create_key()
    return mod


def test_W12_unit_roundtrip_and_format(crypto, tmp_path):
    stored = crypto.seal("Ali Raza", "users.full_name:42")
    assert stored.startswith("enc:v1:") and "Ali" not in stored
    assert crypto.decrypt(stored, "users.full_name:42") == "Ali Raza"
    assert crypto.seal("Ali Raza", "users.full_name:42") != stored            # fresh random nonce each time
    key = (tmp_path / "data_key_v1").read_bytes()
    assert len(key) == 32
    crypto._keys.clear()
    crypto.load_or_create_key()                                              # reloads the same key from the volume
    assert (tmp_path / "data_key_v1").read_bytes() == key
    assert crypto.decrypt(stored, "users.full_name:42") == "Ali Raza"


def test_W12_unit_wrong_aad_fails(crypto):
    stored = crypto.seal("Rent share", "transactions.note:alice")
    with pytest.raises(crypto.Unreadable):
        crypto.decrypt(stored, "transactions.note:mallory")                  # pasted into another sender's row
    with pytest.raises(crypto.Unreadable):
        crypto.decrypt(stored, "users.full_name:alice")                      # or into another column
    assert crypto.reveal(stored, "transactions.note:mallory") == crypto.UNREADABLE


def test_W12_unit_tampered_byte_fails(crypto):
    stored = crypto.seal("Rs 2,000 for lunch", "transactions.note:alice")
    prefix, body = stored[:len("enc:v1:")], stored[len("enc:v1:"):]
    raw = bytearray(crypto._b64u_decode(body))
    raw[20] ^= 0x01                                                          # flip one ciphertext bit
    with pytest.raises(crypto.Unreadable):
        crypto.decrypt(prefix + crypto._b64u(bytes(raw)), "transactions.note:alice")
    with pytest.raises(crypto.Unreadable):
        crypto.decrypt("enc:v9:" + body, "transactions.note:alice")          # unknown key id
    with pytest.raises(crypto.Unreadable):
        crypto.decrypt("enc:v1:@@not-base64@@", "transactions.note:alice")


def test_W12_unit_plaintext_passthrough(crypto):
    assert crypto.decrypt("Opening deposit", "transactions.note:x") == "Opening deposit"
    assert crypto.decrypt(None, "transactions.note:x") is None
    assert crypto.encrypt(None, "transactions.note:x") is None


# ------------------------------------------------------------------ end-to-end
@pytest.fixture
def reset():
    """Same reset as test_security's autouse fixture, but opt-in so the unit tests above need no stack."""
    c, _ = login("ali")
    assert c.post("/api/lab/reset").status_code == 200


def _register(username: str, full_name: str) -> dict:
    r = client().post("/api/auth/register", json={"username": username, "full_name": full_name,
                                                  "password": "blue-kite-harbor-7"})
    assert r.status_code == 201, r.text
    return r.json()


def _stored_name(c, username: str) -> str:
    return next(r["full_name"] for r in c.get("/api/lab/users-table").json()["items"] if r["username"] == username)


def _stored_note(c, ref: str) -> str:
    return next(r["note"] for r in c.get("/api/lab/raw-transactions").json()["items"] if r["ref"] == ref)


def test_W12_full_name_encrypted_at_rest(reset):
    ali, _ = login("ali")
    assert _register("enc_ayesha", "Ayesha Siddiqui")["user"]["full_name"] == "Ayesha Siddiqui"
    stored = _stored_name(ali, "enc_ayesha")
    assert stored.startswith("enc:v1:") and "Ayesha" not in stored          # what a DB dump shows
    me, body = login("enc_ayesha", "blue-kite-harbor-7")
    assert body["user"]["full_name"] == "Ayesha Siddiqui"
    assert me.get("/api/me").json()["user"]["full_name"] == "Ayesha Siddiqui"
    # Seeded rows are encrypted too, and other customers see the plaintext name through the API.
    assert _stored_name(ali, "sara").startswith("enc:v1:")
    assert ali.get("/api/users/lookup", params={"username": "sara"}).json()["full_name"] == "Sara Khan"


def test_W12_transfer_note_encrypted_at_rest(reset):
    ali, _ = login("ali")
    sara, _ = login("sara")
    note = f"Biryani night {uuid.uuid4().hex[:6]}"
    r = send(ali, "sara", 100, tpin=TPIN, note=note)
    assert r.status_code == 201, r.text
    assert r.json()["note"] == note
    stored = _stored_note(ali, r.json()["ref"])
    assert stored.startswith("enc:v1:") and "Biryani" not in stored
    for c in (ali, sara):                                                    # both parties read it in plaintext
        tx = next(t for t in c.get("/api/transactions").json()["items"] if t["ref"] == r.json()["ref"])
        assert tx["note"] == note
        assert tx["counterparty"]["full_name"] in ("Ali Raza", "Sara Khan")


def test_W12_audit_detail_encrypted_and_readable_by_auditor(reset):
    ali, _ = login("ali")
    ref = send(ali, "sara", 100, tpin=TPIN).json()["ref"]
    auditor, _ = login("auditor")
    item = next(i for i in auditor.get("/api/audit", params={"action": "transfer.create"}).json()["items"]
                if i["detail"].get("ref") == ref)
    assert item["detail"]["to"] == "sara"                                    # decrypted for the audit desk


def test_W12_before_after_lab_switch(reset):
    ali, _ = login("ali")
    flag(ali, "encryption_at_rest", False)                                   # before: stored as typed
    _register("enc_plain", "Plain Text Person")
    r_plain = send(ali, "sara", 100, tpin=TPIN, note="readable note")
    flag(ali, "encryption_at_rest", True)                                    # after: ciphertext
    _register("enc_sealed", "Sealed Person")
    r_sealed = send(ali, "sara", 100, tpin=TPIN, note="sealed note")
    assert _stored_name(ali, "enc_plain") == "Plain Text Person"
    assert _stored_note(ali, r_plain.json()["ref"]) == "readable note"
    assert _stored_name(ali, "enc_sealed").startswith("enc:v1:")
    assert _stored_note(ali, r_sealed.json()["ref"]).startswith("enc:v1:")
    # Mixed old and new rows still read correctly through the API.
    notes = {t["ref"]: t["note"] for t in ali.get("/api/transactions").json()["items"]}
    assert notes[r_plain.json()["ref"]] == "readable note" and notes[r_sealed.json()["ref"]] == "sealed note"

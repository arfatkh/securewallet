"""W12: encryption at rest. Sensitive columns are AES-256-GCM ciphertext in Postgres.

A database dump, a stolen backup or a curious DBA sees only ciphertext: the
data-encryption key lives in the keys volume next to the JWT signing key, never
in the database, so the dump alone is not enough.

Stored format (a text value):   enc:v1:<base64url( nonce[12] ‖ ciphertext ‖ tag[16] )>
  v1     key id, so a new key can be added later while old rows stay readable
  nonce  96 random bits per value (NIST SP 800-38D), never reused with the same key
  AAD    where the value lives, e.g. "users.full_name:<user id>". The tag covers it,
         so a ciphertext copied into another row or column fails to decrypt.

Balances and usernames stay plaintext on purpose: balances are summed and locked
inside SQL (transfer_funds, reconcile_ledger), and the username is the login key.
"""
import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import lab, trace
from ..config import settings

KEY_ID = "v1"
PREFIX = "enc:"
UNREADABLE = "[unreadable]"
NONCE_BYTES = 12

_keys: dict[str, bytes] = {}


class Unreadable(Exception):
    """Unknown key id, wrong location (AAD) or a modified ciphertext: the GCM tag did not verify."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_or_create_key() -> None:
    """The data key lives in a volume outside the image, the repo and the database."""
    path = Path(settings.keys_dir) / f"data_key_{KEY_ID}"
    if path.exists():
        key = path.read_bytes()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        key = AESGCM.generate_key(bit_length=256)
        # Created 0600 in one step, so the key is never readable by others, even briefly.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    if len(key) != 32:
        raise RuntimeError(f"{path} is not a 256-bit key")
    _keys[KEY_ID] = key


def is_encrypted(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value: str, aad: str, *, quiet: bool = False) -> str:
    """Always encrypt (seed data, and encrypt() when the control is on)."""
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(_keys[KEY_ID]).encrypt(nonce, value.encode(), aad.encode())
    stored = f"{PREFIX}{KEY_ID}:{_b64u(nonce + sealed)}"
    if not quiet:
        trace.step(f"Encrypt {aad.split(':')[0]} before it is stored", layer="L3", status="pass",
                   data=[("algorithm", "AES-256-GCM (authenticated encryption)"), ("key id", KEY_ID),
                         ("nonce (12 B, random)", nonce.hex()), ("AAD", aad),
                         ("plaintext", f"{len(value.encode())} bytes"),
                         ("ciphertext + tag", f"{len(sealed)} bytes ({len(sealed) - 16} + 16 B tag)"),
                         ("stored value", trace.short(stored, 18, 8))],
                   explain="The database only ever receives ciphertext. The AAD is authenticated but not stored: "
                           "it binds the value to this row and column, so it can't be pasted elsewhere.")
    return stored


def encrypt(value: str | None, aad: str, *, quiet: bool = False) -> str | None:
    if value is None:
        return None
    if not lab.enabled("encryption_at_rest"):
        if not quiet:
            trace.step(f"Store {aad.split(':')[0]} as plaintext (LAB: W12 off)", layer="L3", status="warn",
                       data=[("stored value", trace.short(value, 18, 8))],
                       explain="Anyone with a database dump, a backup or DBA access reads this directly.")
        return value
    return seal(value, aad, quiet=quiet)


def decrypt(value: str | None, aad: str, *, quiet: bool = False) -> str | None:
    """Plaintext (older or lab rows) passes through unchanged; ciphertext must verify or Unreadable is raised."""
    if not is_encrypted(value):
        return value
    try:
        _, kid, body = value.split(":", 2)
        raw = _b64u_decode(body)
        nonce, sealed = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
        plain = AESGCM(_keys[kid]).decrypt(nonce, sealed, aad.encode()).decode()
    except (KeyError, ValueError, InvalidTag) as e:
        trace.step(f"Decrypt {aad.split(':')[0]}: authentication tag rejected", layer="L3", status="fail",
                   data=[("stored value", trace.short(value, 18, 8)), ("AAD", aad),
                         ("reason", "unknown key id" if isinstance(e, KeyError) else "tag mismatch / malformed")],
                   explain="The ciphertext was modified, moved from another row or column, or sealed with another "
                           "key. GCM refuses to return any of it.")
        raise Unreadable(aad) from None
    if not quiet:
        trace.step(f"Decrypt {aad.split(':')[0]}", layer="L3", status="pass",
                   data=[("algorithm", "AES-256-GCM"), ("key id", kid), ("nonce", nonce.hex()), ("AAD", aad),
                         ("ciphertext + tag", f"{len(sealed)} bytes")],
                   checks=[(True, "GCM tag verified: ciphertext unmodified and bound to this row and column")])
    return plain


def reveal(value: str | None, aad: str, *, quiet: bool = False) -> str | None:
    """decrypt() for display: a value that fails to verify is shown as [unreadable] instead of a 500."""
    try:
        return decrypt(value, aad, quiet=quiet)
    except Unreadable:
        return UNREADABLE


def bulk_step(what: str, stored: list[str | None]) -> None:
    """One trace step for a list response, instead of one per decrypted field."""
    values = [v for v in stored if v is not None]
    enc = [v for v in values if is_encrypted(v)]
    trace.step(f"Decrypt {what}", layer="L3", status="pass" if len(enc) == len(values) else "warn",
               data=[("algorithm", "AES-256-GCM, key id " + KEY_ID), ("fields", len(values)),
                     ("stored encrypted", len(enc)), ("stored as plaintext", len(values) - len(enc)),
                     *([("example stored value", trace.short(enc[0], 18, 8))] if enc else [])],
               explain="Each value's GCM tag is verified against its own row and column (AAD) before it is "
                       "returned. Plaintext rows were written while the control was switched off.")

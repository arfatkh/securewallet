"""W2: password storage with argon2id."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .. import trace

# OWASP-recommended argon2id profile: 64 MiB memory, 3 passes, 2 lanes.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

# Verified against when the username does not exist, so a miss costs the same
# time as a hit and response timing cannot be used to enumerate accounts.
_DUMMY_HASH = _hasher.hash("not-a-real-password-dummy")

PLAIN_PREFIX = "plain$"  # only written when the lab switches W2 off

COMMON = {"password", "password1", "password123", "12345678", "123456789", "1234567890", "qwerty123",
          "iloveyou", "admin123", "welcome1", "letmein123", "pakistan", "pakistan123", "11111111",
          "abc12345", "qwertyuiop", "football", "monkey123", "dragon123", "sunshine1"}


def policy_problems(password: str, username: str) -> list[str]:
    problems = []
    if len(password) < 10:
        problems.append("Use at least 10 characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if password.lower() in COMMON:
        problems.append("This password is too common.")
    if username and username.lower() in password.lower():
        problems.append("Don't include your username in the password.")
    return problems


def hash_password(password: str, *, secure: bool = True) -> str:
    if not secure:
        trace.step("Store password (LAB: hashing disabled)", layer="L3", status="warn",
                   data=[("stored value", PLAIN_PREFIX + "•" * len(password))],
                   explain="W2 control is off: the password is written as plain text. "
                           "Anyone who reads the database or a backup now has it.")
        return PLAIN_PREFIX + password
    h = _hasher.hash(password)
    params, salt, digest = h.split("$")[3], h.split("$")[4], h.split("$")[5]
    trace.step("Hash password with argon2id", layer="L3", status="pass",
               data=[("algorithm", "argon2id v19"), ("parameters", params + "  (64 MiB, 3 passes, 2 lanes)"),
                     ("salt (16 B, random)", salt), ("digest (32 B)", trace.short(digest, 12, 6)),
                     ("stored", trace.short(h, 38, 8))],
               explain="Memory-hard and salted: identical passwords get different hashes, and each guess "
                       "costs an attacker 64 MiB of RAM, so cracking a leaked database is slow.")
    return h


def verify_password(stored: str | None, password: str) -> bool:
    if stored is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        trace.step("Verify password (unknown user → dummy hash)", status="fail",
                   explain="The username does not exist, but we still spend one argon2id verification "
                           "so the response time does not reveal that.")
        return False
    if stored.startswith(PLAIN_PREFIX):
        ok = stored[len(PLAIN_PREFIX):] == password
        trace.step("Verify password (LAB: plain-text row)", status="pass" if ok else "fail",
                   explain="This account was created while W2 was off, so its password sits in the DB as text.")
        return ok
    try:
        ok = _hasher.verify(stored, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        ok = False
    parts = stored.split("$")
    trace.step("Verify password with argon2id", status="pass" if ok else "fail",
               data=[("stored hash", trace.short(stored, 38, 8)), ("salt", parts[4] if len(parts) > 5 else "?"),
                     ("parameters", parts[3] if len(parts) > 5 else "?")],
               math=["candidate = argon2id(password, salt, m=65536, t=3, p=2)",
                     f"candidate == stored digest  →  {'✓ match' if ok else '✗ no match'}  (constant-time compare)"],
               explain="The server re-derives the hash from the submitted password and the stored salt. "
                       "The password itself is never stored or logged.")
    return ok

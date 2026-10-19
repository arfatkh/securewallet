"""W11: transaction PIN. Stored like a password (argon2id), checked on every transfer."""
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .. import trace
from .passwords import _hasher  # same argon2id profile as passwords: 64 MiB, 3 passes, 2 lanes

# A 6-digit PIN has only a million values, so the guessable ones are refused outright.
COMMON = {"000000", "111111", "121212", "112233", "123123", "123321", "131313", "159753", "147258",
          "147852", "142536", "159357", "112211", "101010", "202020", "696969", "777777", "520520",
          "654321", "123456", "212121", "232323", "007007", "786786", "786000", "100200", "199999"}


def _is_run(pin: str, step: int) -> bool:
    return all((int(b) - int(a)) % 10 == step % 10 for a, b in zip(pin, pin[1:]))


def weak_pin_problems(pin: str) -> list[str]:
    problems = []
    if len(pin) != 6 or not pin.isdigit():
        return ["Use exactly 6 digits."]
    if len(set(pin)) == 1:
        problems.append("Don't repeat one digit.")
    elif _is_run(pin, 1) or _is_run(pin, -1):
        problems.append("Don't use digits in sequence like 123456 or 654321.")
    elif pin in COMMON or pin[:3] == pin[3:] or pin[:2] * 3 == pin:
        problems.append("This PIN is too common. Pick something harder to guess.")
    return problems


def pin_checks(pin: str) -> list[tuple[bool, str]]:
    """Checklist for the trace. Only pass/fail is shown, never the digits."""
    return [(len(set(pin)) > 1, "not one repeated digit"),
            (not (_is_run(pin, 1) or _is_run(pin, -1)), "not an ascending or descending run"),
            (pin not in COMMON and pin[:3] != pin[3:] and pin[:2] * 3 != pin, "not a common or patterned PIN")]


def hash_tpin(pin: str) -> str:
    h = _hasher.hash(pin)
    params, salt = h.split("$")[3], h.split("$")[4]
    trace.step("Hash transaction PIN with argon2id", layer="L3", status="pass",
               data=[("algorithm", "argon2id v19"), ("parameters", params + "  (64 MiB, 3 passes, 2 lanes)"),
                     ("salt (16 B, random)", salt), ("stored", trace.short(h, 38, 8))],
               explain="The PIN is stored like a password: salted and memory-hard, never as digits. "
                       "Its small keyspace is protected online by the 3-strike lock.")
    return h


def verify_tpin(stored: str | None, pin: str | None) -> bool:
    if not stored or not pin:
        return False
    try:
        ok = _hasher.verify(stored, pin)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        ok = False
    parts = stored.split("$")
    trace.step("Verify transaction PIN with argon2id", layer="L1", status="pass" if ok else "fail",
               data=[("stored hash", trace.short(stored, 38, 8)), ("salt", parts[4] if len(parts) > 5 else "?")],
               math=["candidate = argon2id(pin, salt, m=65536, t=3, p=2)",
                     f"candidate == stored digest  →  {'✓ match' if ok else '✗ no match'}  (constant-time compare)"],
               explain="Something only the account holder knows, checked on every transfer. "
                       "A stolen session token alone can't move money.")
    return ok

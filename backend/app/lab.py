"""Vulnerability lab switches (demo mode only).

Every control is ON by default. The lab can switch one off to show the
weakness ("before"), then back on to retest ("after"). Outside demo mode
`enabled()` always returns True, so the vulnerable branches are unreachable.
"""
from . import db
from .config import settings

FLAGS = [
    # name, weakness, title, description
    ("rls", "W1", "Row-level security",
     "Postgres policies only return wallets and transactions that belong to the requesting user."),
    ("ownership_check", "W1", "Ownership filter in API queries",
     "API queries also filter by the caller's id, a second layer in front of RLS."),
    ("argon2", "W2", "argon2id password hashing",
     "New passwords are stored as salted, memory-hard hashes instead of text."),
    ("login_throttle", "W3", "Login throttling & lockout",
     "Per-IP rate limit plus per-account lockout with exponential back-off."),
    ("jwt_verification", "W4", "Token signature verification",
     "Every request's ES256 signature and claims are verified before anything is trusted."),
    ("amount_validation", "W5", "Amount validation",
     "Amounts must be whole paisa, positive and under the limit, in the API and in the database."),
    ("idempotency", "W6", "Idempotency keys",
     "A retried or replayed transfer request returns the original result instead of paying twice."),
    ("row_locking", "W7", "Atomic transfer with row locks",
     "Both wallets are locked in a fixed order inside one DB transaction."),
    ("step_up", "W8", "Passkey step-up for risky transfers",
     "Large or first-time-payee transfers need a fresh FIDO2 signature bound to that transfer."),
    ("rbac", "W9", "Role-based access",
     "Only the auditor role can read the audit log and run reconciliation."),
    ("tpin", "W11", "Transaction PIN",
     "Every transfer needs the account's 6-digit transaction PIN, checked against an argon2id hash."),
    ("encryption_at_rest", "W12", "Encryption at rest",
     "Names, transfer notes and audit details are stored as AES-256-GCM ciphertext."),
    ("session_timeout", "W13", "Inactivity timeout",
     "A session with no activity for the idle limit is ended by the server."),
    ("session_binding", "W14", "Device-bound session",
     "Refreshing a session needs a signature from a non-extractable key held only by the original browser."),
]


def enabled(name: str) -> bool:
    if not settings.demo_mode:
        return True
    assert db.app_pool is not None
    with db.app_pool.connection() as conn:
        row = conn.execute("SELECT enabled FROM lab_flags WHERE name = %s", (name,)).fetchone()
    return True if row is None else bool(row["enabled"])

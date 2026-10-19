"""Schema migration and demo seed data. Runs as the owner role at startup."""
import datetime as dt
import logging
import uuid
from pathlib import Path

import psycopg

from . import lab
from .config import settings
from .db import owner_conn
from .security import crypto
from .security.passwords import hash_password
from .security.tpin import hash_tpin

log = logging.getLogger("securewallet.migrate")

SCHEMA = Path(__file__).parent / "sql" / "schema.sql"
UPGRADE = Path(__file__).parent / "sql" / "upgrade.sql"  # idempotent; keeps existing data
TOTAL_SUPPLY = 1_000_000_000  # Rs 10,000,000 held by the treasury wallet
DEMO_PASSWORD = "Wallet@2026!"
DEMO_TPIN = "482915"  # W11: every seeded customer's transaction PIN

USERS = [  # username, full name, role
    ("treasury", "SecureWallet Treasury", "system"),
    ("ali", "Ali Raza", "customer"),
    ("sara", "Sara Khan", "customer"),
    ("bilal", "Bilal Ahmed", "customer"),
    ("hina", "Hina Malik", "customer"),
    ("auditor", "Audit Desk", "auditor"),
]

# (days ago, hour, sender, receiver, rupees, note). Opening deposits first.
HISTORY = [
    (24, 10, "treasury", "ali", 260_000, "Opening deposit"),
    (24, 10, "treasury", "sara", 45_000, "Opening deposit"),
    (24, 11, "treasury", "bilal", 18_000, "Opening deposit"),
    (24, 11, "treasury", "hina", 30_000, "Opening deposit"),
    (19, 13, "ali", "sara", 3_500, "Lunch at Savour Foods"),
    (15, 20, "sara", "ali", 1_200, "Chai + samosa run"),
    (12, 9, "ali", "bilal", 4_000, "Cricket kit share"),
    (9, 18, "hina", "ali", 2_750, "Electricity bill split"),
    (6, 21, "ali", "sara", 5_000, "Rent share - September"),
    (3, 16, "bilal", "hina", 1_500, "Book return"),
    (1, 12, "ali", "hina", 2_250, "Birthday gift"),
]


def _schema_exists(conn: psycopg.Connection) -> bool:
    return conn.execute("SELECT to_regclass('public.users') AS t").fetchone()["t"] is not None


def seed(conn: psycopg.Connection) -> None:
    pw_hash = hash_password(DEMO_PASSWORD)
    ids: dict[str, uuid.UUID] = {}
    for username, name, role in USERS:
        uid = uuid.uuid4()
        ids[username] = uid
        conn.execute("INSERT INTO users (id, username, full_name, password_hash, role) VALUES (%s, %s, %s, %s, %s)",
                     (uid, username, crypto.seal(name, f"users.full_name:{uid}", quiet=True),  # W12
                      "!" if role == "system" else pw_hash, role))
        if role != "auditor":
            conn.execute("INSERT INTO wallets (user_id, balance) VALUES (%s, %s)",
                         (uid, TOTAL_SUPPLY if role == "system" else 0))
    conn.execute("INSERT INTO ledger_settings (total_supply) VALUES (%s)", (TOTAL_SUPPLY,))
    conn.execute("UPDATE users SET tpin_hash = %s, tpin_set_at = now() WHERE role = 'customer'",
                 (hash_tpin(DEMO_TPIN),))

    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    for i, (days, hour, s, r, rupees, note) in enumerate(HISTORY):
        amount = rupees * 100
        ts = (now - dt.timedelta(days=days)).replace(hour=hour, minute=(i * 7) % 60)
        conn.execute("UPDATE wallets SET balance = balance - %s WHERE user_id = %s", (amount, ids[s]))
        conn.execute("UPDATE wallets SET balance = balance + %s WHERE user_id = %s", (amount, ids[r]))
        conn.execute("INSERT INTO transactions (ref, sender_id, receiver_id, amount, note, status, created_at) "
                     "VALUES (%s, %s, %s, %s, %s, 'completed', %s)",
                     (f"TX{uuid.uuid4().hex[:10].upper()}", ids[s], ids[r], amount,
                      crypto.seal(note, f"transactions.note:{ids[s]}", quiet=True), ts))  # W12

    for name, weakness, title, desc in lab.FLAGS:
        conn.execute("INSERT INTO lab_flags (name, weakness, title, description) VALUES (%s, %s, %s, %s)",
                     (name, weakness, title, desc))

    # Ali's saved beneficiaries (adding more through the app needs the transaction PIN).
    for payee, nickname in (("sara", "Sara - rent"), ("hina", None)):
        conn.execute("INSERT INTO beneficiaries (user_id, payee_id, nickname) VALUES (%s, %s, %s)",
                     (ids["ali"], ids[payee],
                      crypto.seal(nickname, f"beneficiaries.nickname:{ids['ali']}", quiet=True) if nickname else None))


def reset(conn: psycopg.Connection) -> None:
    """Demo reset: restore every control and the original seed data."""
    conn.execute("ALTER TABLE wallets ENABLE ROW LEVEL SECURITY")
    conn.execute("ALTER TABLE transactions ENABLE ROW LEVEL SECURITY")
    has = conn.execute("SELECT 1 FROM pg_constraint WHERE conname = 'amount_positive'").fetchone()
    conn.execute("TRUNCATE audit_log, idempotency_keys, pending_transfers, refresh_tokens, revoked_jti, "
                 "sessions, dpop_jti, lab_settings, beneficiaries, "
                 "webauthn_challenges, webauthn_credentials, transactions, wallets, ledger_settings, lab_flags, "
                 "users CASCADE")
    if not has:
        conn.execute("ALTER TABLE transactions ADD CONSTRAINT amount_positive CHECK (amount > 0)")
    seed(conn)


def migrate() -> None:
    with owner_conn() as conn:
        if _schema_exists(conn):
            with conn.transaction():
                conn.execute(UPGRADE.read_text(encoding="utf-8"))
            log.info("schema present, upgrades applied")
            return
        with conn.transaction():
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
            conn.execute(UPGRADE.read_text(encoding="utf-8"))
            if settings.seed:
                seed(conn)
        log.info("schema created%s", " and seeded" if settings.seed else "")

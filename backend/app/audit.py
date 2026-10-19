"""W10: append-only audit trail. Every outcome is recorded, rejections included.

W12: the redacted detail is stored encrypted, as {"enc": "enc:v1:…"} in the jsonb column. Its AAD
is the column name only: the row id comes from the sequence at INSERT, after encryption.
"""
import json
import logging
import re
from typing import Any

from . import db, trace
from .security import crypto

log = logging.getLogger("securewallet.audit")

_SECRET_KEYS = re.compile(r"pass(word)?|token|secret|authorization|cookie|signature|assertion|credential|otp|private",
                          re.I)

AAD = "audit_log.detail"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def record(action: str, outcome: str, *, status_code: int | None = None, actor: dict | None = None,
           request_id: str | None = None, ip: str | None = None, detail: dict | None = None) -> None:
    """Written on its own connection so it survives a rollback of the business transaction."""
    safe = redact(detail or {})
    actor = actor or {}
    try:
        sealed = crypto.encrypt(json.dumps(safe), AAD, quiet=True)
        stored = {"enc": sealed} if crypto.is_encrypted(sealed) else safe
        assert db.app_pool is not None
        with db.app_pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO audit_log (request_id, actor_id, actor, role, action, outcome, status_code, ip, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (request_id, actor.get("id"), actor.get("name"), actor.get("role"), action, outcome, status_code, ip,
                 json.dumps(stored))).fetchone()
        trace.step(f"Audit: {action} → {outcome}", lane="Database", layer="L5",
                   status="pass" if outcome in ("success", "created") else "info",
                   data=[("audit_log.id", row["id"]), ("actor", actor.get("name") or "anonymous"),
                         ("status", status_code), ("detail", json.dumps(safe)),
                         ("detail stored as", trace.short(sealed, 18, 8) if stored is not safe
                          else "plaintext jsonb (LAB: W12 off)")],
                   explain="Append-only (a trigger rejects UPDATE/DELETE). Secrets are redacted before writing, "
                           "and the detail is AES-256-GCM encrypted at rest.")
    except Exception:  # auditing must never take the request down with it
        log.exception("audit write failed")

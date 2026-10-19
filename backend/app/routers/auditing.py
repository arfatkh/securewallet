import json

import psycopg
from fastapi import APIRouter, Depends, Query, Request

from .. import db, trace
from ..audit import AAD
from ..deps import Principal, deny, require_role
from ..security import crypto

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _detail(stored):
    """W12: {"enc": "enc:v1:…"} → the original detail. Rows written with the control off pass through."""
    if not (isinstance(stored, dict) and set(stored) == {"enc"} and crypto.is_encrypted(stored["enc"])):
        return stored
    plain = crypto.reveal(stored["enc"], AAD, quiet=True)
    return {"error": plain} if plain == crypto.UNREADABLE else json.loads(plain)


@router.get("")
def audit_log(limit: int = Query(100, ge=1, le=500), action: str | None = None, outcome: str | None = None,
              p: Principal = Depends(require_role("auditor"))):
    where, args = [], []
    if action:
        where.append("action LIKE %s"); args.append(action.replace("%", "") + "%")
    if outcome:
        where.append("outcome = %s"); args.append(outcome)
    with db.session(p.id, p.role) as conn:
        rows = conn.execute("SELECT id, ts, request_id, actor, role, action, outcome, status_code, ip, detail "
                            "FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "")
                            + " ORDER BY id DESC LIMIT %s", [*args, limit]).fetchall()
    # The query selects no names (actor is the plaintext username), so only detail needs decrypting.
    stored = [r["detail"] for r in rows]
    crypto.bulk_step("audit_log.detail", [d["enc"] if isinstance(d, dict) and "enc" in d else json.dumps(d)
                                          for d in stored])
    return {"items": [{**r, "ts": r["ts"].isoformat(), "detail": _detail(r["detail"])} for r in rows]}


@router.get("/reconcile")
def reconcile(request: Request, p: Principal = Depends(require_role("auditor"))):
    try:
        with db.session(p.id, p.role) as conn:
            rows = conn.execute("SELECT * FROM reconcile_ledger()").fetchall()
            supply = conn.execute("SELECT total_supply FROM ledger_settings").fetchone()
    except psycopg.errors.InsufficientPrivilege:
        trace.step("Database refused: reconcile_ledger() requires app.role = 'auditor'", lane="Database",
                   layer="L3", status="fail",
                   explain="Even with the API's role check switched off, the database function enforces the role "
                           "(defence in depth).")
        raise deny(request, 403, "This area is restricted to the audit team.", action="audit.reconcile", principal=p)
    total = sum(r["balance"] for r in rows)
    items = [{"username": r["username"], "balance": r["balance"], "expected": r["expected"],
              "ok": r["balance"] == r["expected"]} for r in rows]
    ok = total == supply["total_supply"] and all(i["ok"] for i in items)
    trace.step("Reconcile balances against the transaction ledger", lane="Database", layer="L6",
               status="pass" if ok else "fail",
               math=[f"Σ wallet balances = {total:,} paisa", f"total supply      = {supply['total_supply']:,} paisa",
                     *[f"{i['username']:<10} balance {i['balance']:>14,}  expected {i['expected']:>14,}  "
                       f"{'✓' if i['ok'] else '✗ MISMATCH'}" for i in items]],
               explain="Every wallet must equal its received minus sent amounts, and money must be conserved. "
                       "A lost update or a forged credit shows up here.")
    return {"ok": ok, "total_balances": total, "total_supply": supply["total_supply"], "items": items}

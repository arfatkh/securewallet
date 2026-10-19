import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import audit, db, lab, trace
from ..deps import Principal, client_ip, current_principal, deny, require_scope
from ..schemas import normalise_username
from ..security import crypto, ratelimit

router = APIRouter(prefix="/api", tags=["wallet"])

TX_SELECT = """
SELECT t.id, t.ref, t.amount, t.note, t.status, t.reason, t.created_at,
       t.sender_id, s.username AS sender_username, s.full_name AS sender_name,
       t.receiver_id, r.username AS receiver_username, r.full_name AS receiver_name
FROM transactions t
JOIN users s ON s.id = t.sender_id
JOIN users r ON r.id = t.receiver_id
"""


def _name(stored: str | None, user_id) -> str | None:
    """W12: users.full_name is ciphertext bound to its own row (AAD users.full_name:<id>)."""
    return crypto.reveal(stored, f"users.full_name:{user_id}", quiet=True)


def _tx_out(row: dict, me: str) -> dict:
    sent = str(row["sender_id"]) == me
    other = ("receiver" if sent else "sender")
    return {"id": str(row["id"]), "ref": row["ref"], "direction": "sent" if sent else "received",
            # The sender wrote the note, so its AAD carries the sender's id.
            "amount": row["amount"], "note": crypto.reveal(row["note"], f"transactions.note:{row['sender_id']}",
                                                           quiet=True),
            "status": row["status"], "reason": row["reason"], "created_at": row["created_at"].isoformat(),
            "counterparty": {"username": row[f"{other}_username"],
                             "full_name": _name(row[f"{other}_name"], row[f"{other}_id"])},
            # Only present when someone else's transaction leaked (lab demo of W1).
            **({} if str(row["receiver_id"]) == me or sent else
               {"leaked": True, "between": f"{row['sender_username']} → {row['receiver_username']}"})}


def _tx_decrypt_step(rows: list[dict]) -> None:
    crypto.bulk_step("transaction notes and names", [v for r in rows for v in
                                                     (r["note"], r["sender_name"], r["receiver_name"])])


def _rls_note(rows: int, table: str) -> None:
    rls = lab.enabled("rls")
    trace.step(f"Row-level security on {table}", lane="Database", layer="L3",
               status="pass" if rls else "warn",
               data=[("policy", f"{table}_read: USING (… = app_uid() OR app_role() = 'auditor')" if rls
                      else "DISABLED (LAB: W1 row-level security off)"), ("rows returned", rows)],
               explain="Postgres adds the policy to every query from wallet_app, even one that forgot its WHERE "
                       "clause." if rls else "Nothing in the database stops a query from reading every row.")


@router.get("/me")
def me(p: Principal = Depends(current_principal)):
    with db.session(p.id, p.role) as conn:
        user = conn.execute("SELECT id, username, full_name, role, created_at, tpin_hash IS NOT NULL AS has_tpin "
                            "FROM users WHERE id = %s",
                            (p.id,)).fetchone()
        wallet = conn.execute("SELECT id, balance, currency, status FROM wallets WHERE user_id = %s",
                              (p.id,)).fetchone()
        passkeys = conn.execute("SELECT count(*) AS n FROM webauthn_credentials", ()).fetchone()["n"]
    if not user:
        raise HTTPException(401, "Please sign in again.")
    return {"user": {"id": str(user["id"]), "username": user["username"],
                     "full_name": crypto.reveal(user["full_name"], f"users.full_name:{user['id']}"),
                     "role": user["role"], "member_since": user["created_at"].isoformat()},
            "wallet": {"id": str(wallet["id"]), "balance": wallet["balance"], "currency": wallet["currency"],
                       "status": wallet["status"]} if wallet else None,
            "passkeys": passkeys, "has_tpin": user["has_tpin"]}


@router.get("/wallets/{wallet_id}")
def get_wallet(wallet_id: uuid.UUID, request: Request, p: Principal = Depends(require_scope("wallet:read"))):
    check = lab.enabled("ownership_check")
    sql = ("SELECT w.id, w.balance, w.currency, w.status, u.id AS user_id, u.username, u.full_name FROM wallets w "
           "JOIN users u ON u.id = w.user_id WHERE w.id = %s" + (" AND w.user_id = %s" if check else ""))
    trace.step("Object-level authorization in the API query", layer="L2", status="pass" if check else "warn",
               data=[("SQL", sql.split("FROM")[0].strip() + " … WHERE w.id = :id"
                      + (" AND w.user_id = :caller" if check else ""))],
               explain="Being signed in is not the same as owning this wallet (OWASP API1: BOLA)." if check else
               "LAB: the API trusts the id in the URL. Only row-level security is left.")
    with db.session(p.id, p.role) as conn:
        row = conn.execute(sql, (wallet_id, p.id) if check else (wallet_id,)).fetchone()
    _rls_note(1 if row else 0, "wallets")
    if not row:
        # 404, not 403: the response is the same whether the wallet exists or is someone else's.
        raise deny(request, 404, "Wallet not found.", action="wallet.read", principal=p,
                   detail={"wallet_id": str(wallet_id)})
    audit.record("wallet.read", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request), detail={"wallet_id": str(wallet_id), "owner": row["username"]})
    return {"id": str(row["id"]), "balance": row["balance"], "currency": row["currency"], "status": row["status"],
            "owner": {"username": row["username"],
                      "full_name": crypto.reveal(row["full_name"], f"users.full_name:{row['user_id']}")}}


@router.get("/transactions")
def list_transactions(limit: int = Query(20, ge=1, le=100), before: str | None = None,
                      direction: str | None = Query(None, pattern="^(sent|received)$"),
                      p: Principal = Depends(require_scope("wallet:read"))):
    check = lab.enabled("ownership_check")
    where, args = [], []
    if check:
        where.append("(t.sender_id = %s OR t.receiver_id = %s)")
        args += [p.id, p.id]
    if direction == "sent":
        where.append("t.sender_id = %s"); args.append(p.id)
    elif direction == "received":
        where.append("t.receiver_id = %s"); args.append(p.id)
    if before:
        where.append("t.created_at < %s::timestamptz"); args.append(before)
    sql = TX_SELECT + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY t.created_at DESC LIMIT %s"
    with db.session(p.id, p.role) as conn:
        rows = conn.execute(sql, [*args, limit]).fetchall()
        pending = conn.execute(
            "SELECT pt.id, pt.user_id, pt.amount, pt.note, pt.status, pt.created_at, pt.expires_at, "
            "pt.receiver_id, u.username, u.full_name "
            "FROM pending_transfers pt JOIN users u ON u.id = pt.receiver_id "
            "WHERE pt.status = 'awaiting_passkey' AND pt.expires_at > now() ORDER BY pt.created_at DESC").fetchall()
    _rls_note(len(rows), "transactions")
    _tx_decrypt_step(rows)
    return {"items": [_tx_out(r, p.id) for r in rows],
            "pending": [{"id": str(x["id"]), "amount": x["amount"],
                         "note": crypto.reveal(x["note"], f"pending_transfers.note:{x['user_id']}", quiet=True),
                         "status": x["status"],
                         "created_at": x["created_at"].isoformat(), "expires_at": x["expires_at"].isoformat(),
                         "counterparty": {"username": x["username"],
                                          "full_name": _name(x["full_name"], x["receiver_id"])}} for x in pending],
            "next_before": rows[-1]["created_at"].isoformat() if len(rows) == limit else None}


@router.get("/transactions/{tx_id}")
def get_transaction(tx_id: uuid.UUID, request: Request, p: Principal = Depends(require_scope("wallet:read"))):
    check = lab.enabled("ownership_check")
    sql = TX_SELECT + " WHERE t.id = %s" + (" AND (t.sender_id = %s OR t.receiver_id = %s)" if check else "")
    with db.session(p.id, p.role) as conn:
        row = conn.execute(sql, (tx_id, p.id, p.id) if check else (tx_id,)).fetchone()
    _rls_note(1 if row else 0, "transactions")
    if not row:
        raise deny(request, 404, "Transaction not found.", action="transaction.read", principal=p,
                   detail={"tx_id": str(tx_id)})
    _tx_decrypt_step([row])
    return _tx_out(row, p.id)


@router.get("/users/lookup")
def lookup(username: str, request: Request, p: Principal = Depends(require_scope("transfer:write"))):
    allowed, _, retry = ratelimit.hit(f"lookup:{p.id}", 60)
    if not allowed:
        raise HTTPException(429, "Too many lookups. Wait a moment.", headers={"Retry-After": str(int(retry) + 1)})
    u = normalise_username(username)
    with db.session(p.id, p.role) as conn:
        row = conn.execute("SELECT id, username, full_name FROM users WHERE username = %s AND role = 'customer'",
                           (u,)).fetchone()
        paid = row and conn.execute(
            "SELECT 1 FROM transactions WHERE sender_id = %s AND receiver_id = %s AND status = 'completed' LIMIT 1",
            (p.id, row["id"])).fetchone() is not None
    if not row:
        raise HTTPException(404, "No SecureWallet customer with that username.")
    # Deliberately minimal: no wallet id, no balance, no user id.
    return {"username": row["username"],
            "full_name": crypto.reveal(row["full_name"], f"users.full_name:{row['id']}"),
            "is_self": str(row["id"]) == p.id, "paid_before": bool(paid)}


@router.get("/contacts")
def contacts(p: Principal = Depends(require_scope("wallet:read"))):
    with db.session(p.id, p.role) as conn:
        rows = conn.execute("""
            SELECT u.id, u.username, u.full_name, max(t.created_at) AS last
            FROM transactions t
            JOIN users u ON u.id = CASE WHEN t.sender_id = %s THEN t.receiver_id ELSE t.sender_id END
            WHERE (t.sender_id = %s OR t.receiver_id = %s) AND u.role = 'customer'
            GROUP BY u.id, u.username ORDER BY last DESC LIMIT 8""", (p.id, p.id, p.id)).fetchall()
    # Grouped by the primary key, not the name: full_name is ciphertext, not something to group or sort on.
    crypto.bulk_step("contact names", [r["full_name"] for r in rows])
    return {"items": [{"username": r["username"], "full_name": _name(r["full_name"], r["id"])} for r in rows]}

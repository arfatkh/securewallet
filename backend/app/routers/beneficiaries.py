"""Saved payees (beneficiaries). Adding one is PIN-gated (W11), like a transfer.

Taking over a session and quietly adding a mule account as a payee is a classic
step in account takeover (Lecture 1, slides 17 and 27), so the add needs the
transaction PIN and every add/remove is audited. Rows are visible only to their
owner (RLS policy beneficiaries_own) and the nickname is encrypted at rest (W12).
"""
import uuid

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request

from .. import audit, db, trace
from ..deps import Principal, client_ip, require_scope
from ..schemas import BeneficiaryIn
from ..security import crypto
from .tpin import enforce as enforce_tpin

router = APIRouter(prefix="/api/beneficiaries", tags=["beneficiaries"])


def _nick_aad(user_id: str) -> str:
    return f"beneficiaries.nickname:{user_id}"


def _out(row: dict, user_id: str) -> dict:
    return {"id": str(row["id"]), "username": row["username"],
            "full_name": crypto.reveal(row["full_name"], f"users.full_name:{row['payee_id']}", quiet=True),
            "nickname": crypto.reveal(row["nickname"], _nick_aad(user_id), quiet=True) if row["nickname"] else None,
            "added_at": row["created_at"].isoformat()}


@router.get("")
def list_beneficiaries(p: Principal = Depends(require_scope("transfer:write"))):
    with db.session(p.id, p.role) as conn:
        rows = conn.execute("SELECT b.id, b.nickname, b.created_at, b.payee_id, u.username, u.full_name "
                            "FROM beneficiaries b JOIN users u ON u.id = b.payee_id "
                            "ORDER BY b.created_at DESC").fetchall()
    trace.step("Row-level security on beneficiaries", lane="Database", layer="L3", status="pass",
               data=[("policy", "beneficiaries_own: USING (user_id = app_uid())"), ("rows returned", len(rows))],
               explain="The query has no WHERE clause; the database itself returns only this customer's payees.")
    return {"items": [_out(r, p.id) for r in rows]}


@router.post("", status_code=201)
def add_beneficiary(body: BeneficiaryIn, request: Request, p: Principal = Depends(require_scope("transfer:write"))):
    rid, ip = request.state.request_id, client_ip(request)
    # PIN first, before the username is even looked up, so the endpoint can't be used
    # to probe usernames without the PIN.
    denied = enforce_tpin(p, body.tpin, rid, ip, action="beneficiary.add",
                          doing="adding a beneficiary", to_do="to add a beneficiary")
    if denied is not None:
        return denied

    with db.session(p.id, p.role) as conn:
        payee = conn.execute("SELECT id, username, full_name FROM users WHERE username = %s AND role = 'customer'",
                             (body.username,)).fetchone()
        trace.step("Validate the payee", layer="L2", status="pass" if payee and str(payee["id"]) != p.id else "fail",
                   checks=[(payee is not None, f"'{body.username}' is a SecureWallet customer"),
                           (payee is None or str(payee["id"]) != p.id, "payee is not yourself")])
        if payee is None:
            raise HTTPException(404, "No SecureWallet customer with that username.")
        if str(payee["id"]) == p.id:
            raise HTTPException(422, "You can't add yourself as a beneficiary.")
        stored_nick = crypto.encrypt(body.nickname, _nick_aad(p.id)) if body.nickname else None
        try:
            with conn.transaction():
                row = conn.execute("INSERT INTO beneficiaries (user_id, payee_id, nickname) VALUES (%s, %s, %s) "
                                   "RETURNING id, nickname, created_at, payee_id",
                                   (p.id, payee["id"], stored_nick)).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, f"@{payee['username']} is already one of your beneficiaries.")
        trace.step("Save beneficiary (RLS insert policy)", lane="Database", layer="L3", status="pass",
                   data=[("policy", "beneficiaries_own: WITH CHECK (user_id = app_uid())"),
                         ("nickname stored as", trace.short(stored_nick, 18, 8) if stored_nick else "none")],
                   explain="A customer can only add payees to their own list.")
    audit.record("beneficiary.add", "success", status_code=201, actor=p.actor(), request_id=rid, ip=ip,
                 detail={"payee": payee["username"]})
    return _out({**row, "username": payee["username"], "full_name": payee["full_name"]}, p.id)


@router.delete("/{beneficiary_id}")
def remove_beneficiary(beneficiary_id: uuid.UUID, request: Request,
                       p: Principal = Depends(require_scope("transfer:write"))):
    with db.session(p.id, p.role) as conn:
        gone = conn.execute("DELETE FROM beneficiaries WHERE id = %s RETURNING payee_id", (beneficiary_id,)).fetchone()
    if not gone:  # not found, or someone else's (RLS hides it): same answer
        raise HTTPException(404, "Beneficiary not found.")
    audit.record("beneficiary.remove", "success", status_code=200, actor=p.actor(),
                 request_id=request.state.request_id, ip=client_ip(request),
                 detail={"beneficiary_id": str(beneficiary_id)})
    return {"ok": True}

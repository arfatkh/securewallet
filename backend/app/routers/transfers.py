import datetime as dt
import hashlib
import json
import os
import uuid

import psycopg
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from .. import audit, db, lab, trace
from ..config import settings
from ..deps import Principal, client_ip, require_scope
from ..schemas import AssertionIn, TransferIn
from ..security import crypto, passkeys, risk

from .tpin import enforce as enforce_tpin

router = APIRouter(prefix="/api/transfers", tags=["transfers"])

STEPUP_TTL = dt.timedelta(minutes=5)


def rs(paisa: int) -> str:
    return f"Rs {paisa / 100:,.2f}"


def _canonical(pending_id: str, sender: str, receiver: str, amount: int, note: str | None, exp: int) -> bytes:
    return json.dumps({"pending_id": pending_id, "from": sender, "to": receiver, "amount": amount,
                       "note": note or "", "exp": exp}, sort_keys=True, separators=(",", ":")).encode()


def _idem_seal(result: dict, user_id: str, key: str) -> dict:
    """W12: the stored replay copies the note and payee name, so it is encrypted at rest as well."""
    sealed = crypto.encrypt(json.dumps(result), f"idempotency_keys.response:{user_id}:{key}", quiet=True)
    return {"enc": sealed} if crypto.is_encrypted(sealed) else result


def _idem_open(stored: dict, user_id: str, key: str) -> dict:
    if not (isinstance(stored, dict) and set(stored) == {"enc"}):
        return stored
    try:
        return json.loads(crypto.decrypt(stored["enc"], f"idempotency_keys.response:{user_id}:{key}"))
    except crypto.Unreadable:
        raise HTTPException(409, "This request conflicts with an earlier one. Start a new transfer.")


def _execute(conn: psycopg.Connection, receiver_id, amount: int, note: str | None, receiver_name: str) -> dict:
    """Call the SECURITY DEFINER function: the only code path that changes balances."""
    locking = lab.enabled("row_locking")
    # W12: the note reaches the database sealed. Its AAD names the sender exactly as transfer_funds()
    # will (app_uid()), so the ciphertext can't be moved onto another sender's transaction.
    sender = conn.execute("SELECT app_uid() AS id").fetchone()["id"]
    stored_note = crypto.encrypt(note, f"transactions.note:{sender}")
    try:
        with conn.transaction():  # savepoint: a raised DB error leaves the outer transaction usable
            row = conn.execute("SELECT * FROM transfer_funds(%s, %s, %s)",
                               (receiver_id, amount, stored_note)).fetchone()
    except psycopg.errors.InvalidParameterValue as e:
        trace.step("Database re-validation rejected the transfer", lane="Database", layer="L3", status="fail",
                   data=[("reason", e.diag.message_primary)],
                   explain="transfer_funds() checks the amount again: the database does not trust the API either.")
        raise HTTPException(422, e.diag.message_primary.capitalize() + ".")
    except psycopg.errors.CheckViolation as e:
        trace.step("Database constraint rejected the write", lane="Database", layer="L3", status="fail",
                   data=[("constraint", e.diag.constraint_name)])
        raise HTTPException(422, "This transfer isn't allowed.")
    trace.step("Atomic transfer in one database transaction", lane="Database", layer="L3",
               status="pass" if row["tx_status"] == "completed" else "fail",
               math=["BEGIN;",
                     ("SELECT … FROM wallets WHERE user_id IN (sender, receiver) ORDER BY user_id FOR UPDATE;"
                      if row["locked"] else "SELECT … FROM wallets …;   -- LAB: no row locks, pg_sleep(0.3)"),
                     f"sender balance   {rs(row['sender_before']):>18}  →  {rs(row['sender_after'])}",
                     f"receiver balance {'(hidden by RLS)':>18}  →  +{rs(amount) if row['tx_status'] == 'completed' else 'Rs 0.00'}",
                     "CHECK (balance >= 0) ✓" if row["tx_status"] == "completed" else f"-- {row['tx_reason']}",
                     f"INSERT INTO transactions (ref = {row['tx_ref']}, status = {row['tx_status']});",
                     "COMMIT;"],
               explain=("Debit and credit happen together or not at all, and the row locks make parallel requests "
                        "queue instead of both spending the same balance." if locking else
                        "LAB: without locks, parallel transfers read the same starting balance and overwrite each "
                        "other (lost update)."))
    return {"id": str(row["tx_id"]), "ref": row["tx_ref"], "status": row["tx_status"], "reason": row["tx_reason"],
            "amount": amount, "note": note, "balance_after": row["sender_after"],
            "counterparty": {"username": receiver_name}}


@router.post("")
def create_transfer(body: TransferIn, request: Request,
                    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
                    p: Principal = Depends(require_scope("transfer:write"))):
    rid, ip = request.state.request_id, client_ip(request)
    # ---- W11: transaction PIN, checked before anything else (and before risk, so the
    # passkey path needs it too). Its own transaction commits the wrong-PIN counter.
    denied = enforce_tpin(p, body.tpin, rid, ip)
    if denied is not None:
        return denied
    use_idem = lab.enabled("idempotency")
    if use_idem and (not idempotency_key or not 8 <= len(idempotency_key) <= 80):
        raise HTTPException(400, "Missing Idempotency-Key header.")
    # The PIN is a secret and not part of "the same request": a retry with a re-typed PIN still matches.
    request_hash = hashlib.sha256(body.model_dump_json(exclude={"tpin"}).encode()).hexdigest()

    with db.session(p.id, p.role) as conn:
        # ---- W6: idempotency. The INSERT takes the unique-key lock, so a concurrent
        # duplicate waits here until the first request commits, then sees its result.
        if use_idem:
            fresh = conn.execute("INSERT INTO idempotency_keys (user_id, key, request_hash) VALUES (%s, %s, %s) "
                                 "ON CONFLICT DO NOTHING RETURNING key", (p.id, idempotency_key, request_hash)).fetchone()
            if not fresh:
                prior = conn.execute("SELECT request_hash, status_code, response FROM idempotency_keys "
                                     "WHERE user_id = %s AND key = %s", (p.id, idempotency_key)).fetchone()
                same = prior["request_hash"] == request_hash
                trace.step("Idempotency-Key lookup: seen before", lane="Database", layer="L2",
                           status="pass" if same and prior["response"] else "fail",
                           data=[("key", idempotency_key), ("request hash", trace.short(request_hash, 12, 6)),
                                 ("stored hash", trace.short(prior["request_hash"], 12, 6))],
                           explain="Same request retried: the stored result is returned and nothing is paid twice."
                           if same else "Same key, different body: rejected as a conflict.")
                if not same:
                    raise HTTPException(409, "This request conflicts with an earlier one. Start a new transfer.")
                if prior["response"] is None:
                    raise HTTPException(409, "This transfer is still being processed.")
                audit.record("transfer.create", "idempotent_replay", status_code=prior["status_code"],
                             actor=p.actor(), request_id=rid, ip=ip, detail={"key": idempotency_key})
                return JSONResponse(_idem_open(prior["response"], p.id, idempotency_key),
                                    status_code=prior["status_code"],
                                    headers={"Idempotent-Replayed": "true"})
            trace.step("Idempotency-Key lookup: new request", lane="Database", layer="L2", status="info",
                       data=[("key", idempotency_key), ("request hash", trace.short(request_hash, 12, 6))])
        else:
            trace.step("Idempotency skipped (LAB: W6 off)", layer="L2", status="warn",
                       explain="A double-click, network retry or replayed request will pay again.")

        # ---- recipient
        receiver = conn.execute("SELECT id, username, full_name FROM users WHERE username = %s AND role = 'customer'",
                                (body.to_username,)).fetchone()
        # ---- W5: server-side validation (the browser's checks are only for convenience)
        validate = lab.enabled("amount_validation")
        rules = [(isinstance(body.amount, int), "amount is a whole number of paisa (no floats)"),
                 (body.amount >= 1, "amount ≥ Rs 0.01"),
                 (body.amount <= settings.max_transfer, f"amount ≤ {rs(settings.max_transfer)} per transfer"),
                 (receiver is not None, f"recipient '{body.to_username}' is a customer"),
                 (receiver is None or str(receiver["id"]) != p.id, "recipient is not yourself")]
        failed = [text for ok, text in rules if not ok]
        amount_failed = [t for t in failed if t.startswith("amount")]
        trace.step("Validate the request on the server", layer="L2",
                   status="pass" if not failed else ("fail" if validate or not amount_failed else "warn"),
                   checks=rules, explain=None if not failed or validate else
                   "LAB: amount checks are off, so this goes straight to the database.")
        if receiver is None:
            raise HTTPException(404, "No SecureWallet customer with that username.")
        if str(receiver["id"]) == p.id:
            raise HTTPException(422, "You can't send money to yourself.")
        if amount_failed and validate:
            audit.record("transfer.create", "rejected", status_code=422, actor=p.actor(), request_id=rid, ip=ip,
                         detail={"to": body.to_username, "amount": body.amount, "reason": amount_failed[0]})
            raise HTTPException(422, "Enter an amount between Rs 0.01 and Rs 500,000.")

        # ---- W8: risk engine → step-up
        paid_before = conn.execute("SELECT 1 FROM transactions WHERE sender_id = %s AND receiver_id = %s "
                                   "AND status = 'completed' LIMIT 1", (p.id, receiver["id"])).fetchone() is not None
        r = risk.assess(body.amount, paid_before)
        trace.step(f"Risk engine → {r.level}", layer="L2", status="pass" if r.level == "LOW" else "warn",
                   data=[("signals", ", ".join(r.signals) or "none"),
                         ("rules", f"amount > {rs(settings.stepup_amount)}  |  new payee and amount > "
                                   f"{rs(settings.new_payee_amount)}"),
                         ("decision", "proceed" if r.level == "LOW" else "passkey step-up required")])

        if r.needs_step_up and lab.enabled("step_up"):
            creds = conn.execute("SELECT id, transports FROM webauthn_credentials").fetchall()
            if not creds:
                trace.step("Step-up impossible: no passkey registered", status="fail")
                audit.record("transfer.create", "passkey_required", status_code=403, actor=p.actor(),
                             request_id=rid, ip=ip, detail={"to": body.to_username, "amount": body.amount})
                raise HTTPException(403, "Add a passkey in Security to send this amount.")
            pending_id = str(uuid.uuid4())
            exp = dt.datetime.now(dt.timezone.utc) + STEPUP_TTL
            nonce = os.urandom(16)
            canonical = _canonical(pending_id, p.id, str(receiver["id"]), body.amount, body.note, int(exp.timestamp()))
            challenge = hashlib.sha256(nonce + canonical).digest()
            conn.execute("INSERT INTO pending_transfers (id, user_id, receiver_id, amount, note, nonce, challenge, "
                         "risk, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (pending_id, p.id, receiver["id"], body.amount,
                          crypto.encrypt(body.note, f"pending_transfers.note:{p.id}"), nonce, challenge,
                          json.dumps(r.as_dict()), exp))
            options = generate_authentication_options(
                rp_id=settings.rp_id, challenge=challenge, timeout=120000,
                user_verification=UserVerificationRequirement.REQUIRED,
                allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(c["id"])) for c in creds])
            options_json = options_to_json(options)
            trace.step("Bind a passkey challenge to this exact transfer", layer="L1", status="info",
                       data=[("pending transfer", pending_id), ("canonical transfer", canonical.decode()),
                             ("nonce (16 B)", nonce.hex())],
                       math=["challenge = SHA-256( nonce ‖ canonical_transfer )",
                             f"          = {challenge.hex()}",
                             f"base64url = {bytes_to_base64url(challenge)}"],
                       explain="Nothing has moved yet (202). The signature the device returns covers this challenge, "
                               "so it approves only this amount to this person, once, within 5 minutes.")
            passkeys.options_step("Send WebAuthn request options to the browser", options_json)
            result = {"status": "awaiting_passkey", "pending_id": pending_id,
                      "risk": r.as_dict(), "amount": body.amount,
                      "counterparty": {"username": receiver["username"],
                                       "full_name": crypto.reveal(receiver["full_name"],
                                                                  f"users.full_name:{receiver['id']}")},
                      "expires_at": exp.isoformat(), "options": json.loads(options_json)}
            code = 202
            audit.record("transfer.stepup_requested", "pending", status_code=202, actor=p.actor(), request_id=rid,
                         ip=ip, detail={"to": body.to_username, "amount": body.amount, "signals": r.signals})
        else:
            if r.needs_step_up:
                trace.step("Step-up skipped (LAB: W8 off)", layer="L1", status="warn",
                           explain="A stolen password or token is enough to move this amount.")
            result = _execute(conn, receiver["id"], body.amount, body.note, receiver["username"])
            result["counterparty"]["full_name"] = crypto.reveal(receiver["full_name"],
                                                                f"users.full_name:{receiver['id']}")
            code = 201 if result["status"] == "completed" else 422
            audit.record("transfer.create", "success" if code == 201 else "failed", status_code=code,
                         actor=p.actor(), request_id=rid, ip=ip,
                         detail={"to": body.to_username, "amount": body.amount, "ref": result["ref"],
                                 "reason": result["reason"]})

        if use_idem:
            conn.execute("UPDATE idempotency_keys SET status_code = %s, response = %s WHERE user_id = %s AND key = %s",
                         (code, json.dumps(_idem_seal(result, p.id, idempotency_key)), p.id, idempotency_key))
    return JSONResponse(result, status_code=code)


@router.post("/{pending_id}/confirm")
def confirm_transfer(pending_id: uuid.UUID, body: AssertionIn, request: Request,
                     p: Principal = Depends(require_scope("transfer:write"))):
    rid, ip = request.state.request_id, client_ip(request)
    with db.session(p.id, p.role) as conn:
        pt = conn.execute("SELECT pt.*, u.username, u.full_name FROM pending_transfers pt "
                          "JOIN users u ON u.id = pt.receiver_id WHERE pt.id = %s FOR UPDATE OF pt",
                          (pending_id,)).fetchone()
        if not pt:
            raise HTTPException(404, "Transfer not found.")
        if pt["status"] != "awaiting_passkey":
            raise HTTPException(409, "This transfer was already handled.")
        if pt["expires_at"] < dt.datetime.now(dt.timezone.utc):
            conn.execute("UPDATE pending_transfers SET status = 'expired' WHERE id = %s", (pending_id,))
            expired = True
        else:
            expired = False
    if expired:
        raise HTTPException(410, "Approval window expired. Start the transfer again.")

    with db.session(p.id, p.role) as conn:
        pt = conn.execute("SELECT pt.*, u.username, u.full_name FROM pending_transfers pt "
                          "JOIN users u ON u.id = pt.receiver_id WHERE pt.id = %s AND pt.status = 'awaiting_passkey' "
                          "FOR UPDATE OF pt", (pending_id,)).fetchone()
        if not pt:
            raise HTTPException(409, "This transfer was already handled.")
        # W12: the challenge was built from the plaintext note, so it is rebuilt from the plaintext too.
        try:
            note = crypto.decrypt(pt["note"], f"pending_transfers.note:{pt['user_id']}")
        except crypto.Unreadable:
            raise HTTPException(409, "This transfer can't be verified. Start it again.")
        canonical = _canonical(str(pt["id"]), p.id, str(pt["receiver_id"]), pt["amount"], note,
                               int(pt["expires_at"].timestamp()))
        recomputed = hashlib.sha256(bytes(pt["nonce"]) + canonical).digest()
        trace.step("Recompute the challenge from the stored transfer", layer="L1",
                   status="pass" if recomputed == bytes(pt["challenge"]) else "fail",
                   data=[("canonical transfer", canonical.decode())],
                   math=[f"SHA-256(nonce ‖ canonical) = {recomputed.hex()}",
                         f"stored challenge          = {bytes(pt['challenge']).hex()}"],
                   explain="The server trusts only its own copy of the amount and payee, never the browser's.")

        cred_id = body.credential.get("rawId") or body.credential.get("id") or ""
        try:
            cred_bytes = base64url_to_bytes(cred_id)
        except Exception:
            raise HTTPException(400, "Malformed passkey response.")
        cred = conn.execute("SELECT id, public_key, sign_count, nickname FROM webauthn_credentials WHERE id = %s",
                            (cred_bytes,)).fetchone()
        trace.step("Look up the passkey (RLS: your own passkeys only)", lane="Database", layer="L3",
                   status="pass" if cred else "fail",
                   data=[("credential id", trace.short(cred_bytes.hex(), 12, 6)),
                         ("passkey", cred["nickname"] if cred else "not one of yours")])
        if not cred:
            raise HTTPException(400, "That passkey isn't registered to your account.")
        try:
            resp = body.credential["response"]
            passkeys.client_data_step(base64url_to_bytes(resp["clientDataJSON"]), "webauthn.get", recomputed)
            passkeys.auth_data_bytes_step(base64url_to_bytes(resp["authenticatorData"]), "authenticatorData byte map")
        except (KeyError, ValueError):
            raise HTTPException(400, "Malformed passkey response.")
        passkeys.signature_math_step(body.credential, bytes(cred["public_key"]))
        try:
            verified = verify_authentication_response(
                credential=body.credential, expected_challenge=recomputed, expected_rp_id=settings.rp_id,
                expected_origin=settings.expected_origins, credential_public_key=bytes(cred["public_key"]),
                credential_current_sign_count=cred["sign_count"], require_user_verification=True)
        except Exception as e:
            trace.step("WebAuthn verification failed", status="fail", data=[("reason", str(e))])
            audit.record("transfer.stepup", "failed", status_code=400, actor=p.actor(), request_id=rid, ip=ip,
                         detail={"pending_id": str(pending_id), "reason": str(e)})
            raise HTTPException(400, "Passkey verification failed.")
        trace.step("Step-up checklist (FIDO2 slide 9)", layer="L1", status="pass",
                   checks=[(True, "signature valid for the stored public key"),
                           (True, "challenge matches this pending transfer"),
                           (True, "credential belongs to you"), (True, f"origin and rpId = {settings.rp_id}"),
                           (True, "user verified on the device (UV flag)"),
                           (True, f"signCount {verified.new_sign_count} vs stored {cred['sign_count']} (clone check)")])
        conn.execute("UPDATE webauthn_credentials SET sign_count = %s, last_used_at = now() WHERE id = %s",
                     (verified.new_sign_count, cred["id"]))
        result = _execute(conn, pt["receiver_id"], pt["amount"], note, pt["username"])
        result["counterparty"]["full_name"] = crypto.reveal(pt["full_name"], f"users.full_name:{pt['receiver_id']}")
        conn.execute("UPDATE pending_transfers SET status = %s, tx_id = %s WHERE id = %s",
                     ("completed" if result["status"] == "completed" else "failed", result["id"], pending_id))
    code = 201 if result["status"] == "completed" else 422
    audit.record("transfer.create", "success" if code == 201 else "failed", status_code=code, actor=p.actor(),
                 request_id=rid, ip=ip, detail={"to": pt["username"], "amount": pt["amount"], "ref": result["ref"],
                                                "step_up": "passkey"})
    return JSONResponse(result, status_code=code)


@router.post("/{pending_id}/cancel")
def cancel_transfer(pending_id: uuid.UUID, request: Request, p: Principal = Depends(require_scope("transfer:write"))):
    with db.session(p.id, p.role) as conn:
        n = conn.execute("UPDATE pending_transfers SET status = 'cancelled' "
                         "WHERE id = %s AND status = 'awaiting_passkey'", (pending_id,)).rowcount
    if not n:
        raise HTTPException(404, "Transfer not found.")
    audit.record("transfer.stepup", "cancelled", status_code=200, actor=p.actor(),
                 request_id=request.state.request_id, ip=client_ip(request), detail={"pending_id": str(pending_id)})
    return {"ok": True}

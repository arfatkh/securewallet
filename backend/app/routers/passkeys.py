import datetime as dt
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, decode_credential_public_key, parse_cbor
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .. import audit, db, trace
from ..config import settings
from ..deps import Principal, client_ip, require_scope
from ..schemas import PasskeyVerifyIn
from ..security import crypto, passkeys

router = APIRouter(prefix="/api/passkeys", tags=["passkeys"])


@router.get("")
def list_passkeys(p: Principal = Depends(require_scope("passkey:manage"))):
    with db.session(p.id, p.role) as conn:
        rows = conn.execute("SELECT id, nickname, created_at, last_used_at, transports FROM webauthn_credentials "
                            "ORDER BY created_at").fetchall()
    return {"items": [{"id": bytes_to_base64url(bytes(r["id"])), "nickname": r["nickname"],
                       "created_at": r["created_at"].isoformat(),
                       "last_used_at": r["last_used_at"].isoformat() if r["last_used_at"] else None,
                       "transports": r["transports"] or []} for r in rows]}


@router.post("/register/options")
def register_options(p: Principal = Depends(require_scope("passkey:manage"))):
    with db.session(p.id, p.role) as conn:
        user = conn.execute("SELECT username, full_name FROM users WHERE id = %s", (p.id,)).fetchone()
        existing = conn.execute("SELECT id FROM webauthn_credentials").fetchall()
        options = generate_registration_options(
            rp_id=settings.rp_id, rp_name=settings.rp_name, user_id=uuid.UUID(p.id).bytes,
            user_name=user["username"], timeout=120000,
            user_display_name=crypto.reveal(user["full_name"], f"users.full_name:{p.id}"),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256,
                                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256],
            exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["id"])) for r in existing])
        conn.execute("INSERT INTO webauthn_challenges (user_id, challenge, expires_at) VALUES (%s, %s, %s)",
                     (p.id, options.challenge, dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)))
    options_json = options_to_json(options)
    passkeys.options_step("Create registration options (fresh challenge, stored server-side)", options_json)
    return json.loads(options_json)


@router.post("/register/verify", status_code=201)
def register_verify(body: PasskeyVerifyIn, request: Request, p: Principal = Depends(require_scope("passkey:manage"))):
    with db.session(p.id, p.role) as conn:
        ch = conn.execute("SELECT id, challenge FROM webauthn_challenges WHERE used_at IS NULL AND expires_at > now() "
                          "ORDER BY expires_at DESC LIMIT 1 FOR UPDATE").fetchone()
        if not ch:
            raise HTTPException(400, "The request expired. Try adding the passkey again.")
        # Single use: consumed whether or not verification succeeds.
        conn.execute("UPDATE webauthn_challenges SET used_at = now() WHERE id = %s", (ch["id"],))
    try:
        resp = body.credential["response"]
        passkeys.client_data_step(base64url_to_bytes(resp["clientDataJSON"]), "webauthn.create", bytes(ch["challenge"]))
        att = parse_cbor(base64url_to_bytes(resp["attestationObject"]))
        passkeys.auth_data_bytes_step(att["authData"], "authenticatorData byte map (with new public key)")
        verified = verify_registration_response(
            credential=body.credential, expected_challenge=bytes(ch["challenge"]), expected_rp_id=settings.rp_id,
            expected_origin=settings.expected_origins, require_user_verification=True)
    except Exception as e:
        trace.step("Registration verification failed", status="fail", data=[("reason", str(e))])
        audit.record("passkey.register", "failed", status_code=400, actor=p.actor(),
                     request_id=request.state.request_id, ip=client_ip(request), detail={"reason": str(e)})
        raise HTTPException(400, "This passkey couldn't be verified. Try again.")

    key = decode_credential_public_key(verified.credential_public_key)
    trace.step("Store the public key (the private key stays on the device)", lane="Database", layer="L3",
               status="pass",
               data=[("credential id", trace.short(verified.credential_id.hex(), 12, 6)),
                     ("algorithm", "ES256 (ECDSA P-256)" if getattr(key, "x", None) else str(getattr(key, "alg", "?"))),
                     ("public key Q.x", trace.short(key.x.hex()) if getattr(key, "x", None) else "-"),
                     ("public key Q.y", trace.short(key.y.hex()) if getattr(key, "y", None) else "-"),
                     ("attestation format", verified.fmt), ("aaguid", verified.aaguid),
                     ("user verified", verified.user_verified)],
               explain="Only a public key is shared with the bank. A stolen database gives an attacker nothing "
                       "they can sign in with.")
    transports = (body.credential.get("response") or {}).get("transports") or []
    with db.session(p.id, p.role) as conn:
        conn.execute("INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, transports, nickname, "
                     "aaguid) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                     (verified.credential_id, p.id, verified.credential_public_key, verified.sign_count,
                      [str(t) for t in transports][:5], body.nickname.strip(), verified.aaguid))
    audit.record("passkey.register", "success", status_code=201, actor=p.actor(),
                 request_id=request.state.request_id, ip=client_ip(request), detail={"nickname": body.nickname})
    return {"ok": True}


@router.delete("/{cred_id}")
def delete_passkey(cred_id: str, request: Request, p: Principal = Depends(require_scope("passkey:manage"))):
    try:
        raw = base64url_to_bytes(cred_id)
    except Exception:
        raise HTTPException(404, "Passkey not found.")
    with db.session(p.id, p.role) as conn:
        n = conn.execute("DELETE FROM webauthn_credentials WHERE id = %s", (raw,)).rowcount
    if not n:
        raise HTTPException(404, "Passkey not found.")
    audit.record("passkey.delete", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request))
    return {"ok": True}

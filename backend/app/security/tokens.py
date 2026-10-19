"""W4: ES256-signed access tokens (JWS) and rotating refresh tokens."""
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .. import trace
from ..config import settings
from . import ecdsa_edu

SCOPES = {
    "customer": "wallet:read transfer:write passkey:manage",
    "auditor": "audit:read",
}

_private_key: ec.EllipticCurvePrivateKey | None = None
_kid = ""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_or_create_key() -> None:
    """The signing key lives in a volume outside the image and the repo."""
    global _private_key, _kid
    path = Path(settings.keys_dir) / "jwt_es256.pem"
    if path.exists():
        _private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        _private_key = ec.generate_private_key(ec.SECP256R1())
        path.write_bytes(_private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
        os.chmod(path, 0o600)
    der = _private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    _kid = "k-" + hashlib.sha256(der).hexdigest()[:10]


def _pub_numbers() -> ec.EllipticCurvePublicNumbers:
    return _private_key.public_key().public_numbers()


def jwks() -> dict:
    n = _pub_numbers()
    return {"keys": [{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": _kid,
                      "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}]}


def issue_access_token(user: dict, amr: list[str], sid: str | None = None) -> tuple[str, dict]:
    now = int(time.time())
    claims = {"iss": settings.jwt_issuer, "sub": str(user["id"]), "aud": settings.jwt_audience,
              "iat": now, "nbf": now, "exp": now + settings.access_ttl_seconds, "jti": secrets.token_hex(12),
              "role": user["role"], "name": user["username"], "scope": SCOPES.get(user["role"], ""), "amr": amr,
              **({"sid": sid} if sid else {})}
    token = jwt.encode(claims, _private_key, algorithm="ES256", headers={"kid": _kid})
    if trace.active():
        h, p, s = token.split(".")
        z = hashlib.sha256(f"{h}.{p}".encode()).hexdigest()
        raw = b64u_decode(s)
        trace.step("Sign access token (JWT, ES256)", status="pass", layer="L1",
                   jwt={"header": h, "payload": p, "signature": s},
                   data=[("header", json.dumps({"alg": "ES256", "kid": _kid, "typ": "JWT"})),
                         ("claims", json.dumps(claims)), ("lifetime", f"{settings.access_ttl_seconds // 60} minutes")],
                   math=[f"z = SHA-256( b64url(header) + '.' + b64url(payload) ) = {trace.short(z, 14, 8)}",
                         "k = fresh secret random nonce;  (x₁, y₁) = k·G;  r = x₁ mod n",
                         f"r = {trace.short(raw[:32], 14, 8)}",
                         "s = k⁻¹ · (z + r·d) mod n        (d = issuer private key, never leaves the server)",
                         f"s = {trace.short(raw[32:], 14, 8)}",
                         "signature = r ‖ s  (64 bytes, base64url)"],
                   explain="Signing gives integrity and authenticity, not secrecy: anyone can base64-decode the "
                           "payload, but nobody without the private key can change it and produce a valid signature.")
    return token, claims


class TokenError(Exception):
    pass


def verify_access_token(token: str, *, verify_signature: bool = True) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        trace.step("Parse JWT", status="fail", explain="A JWT has exactly three dot-separated parts.")
        raise TokenError("malformed token")
    h, p, s = parts
    try:
        header = json.loads(b64u_decode(h))
        payload = json.loads(b64u_decode(p))
        sig = b64u_decode(s)
    except Exception:
        trace.step("Parse JWT", status="fail", explain="Segments are not valid base64url JSON.")
        raise TokenError("malformed token")
    trace.step("Parse JWT (decode only, nothing trusted yet)", status="info", layer="L1",
               jwt={"header": h, "payload": p, "signature": s},
               data=[("header", json.dumps(header)), ("sub", payload.get("sub")), ("scope", payload.get("scope"))],
               explain="Base64URL decoding is not decryption and not validation. Trust starts after the signature check.")

    if not verify_signature:
        trace.step("Signature check skipped (LAB: W4 off)", status="warn",
                   explain="The server believes whatever the payload says, so anyone can edit `sub` and become "
                           "another customer.")
        return payload

    if header.get("alg") != "ES256" or header.get("kid") != _kid:
        trace.step("Check algorithm and key id", status="fail",
                   checks=[(header.get("alg") == "ES256", f"alg == ES256 (got {header.get('alg')!r})"),
                           (header.get("kid") == _kid, f"kid == {_kid} (got {header.get('kid')!r})")],
                   explain="The algorithm is pinned, which blocks `alg: none` and HS256 key-confusion tricks.")
        raise TokenError("unexpected algorithm or key")

    if trace.active() and len(sig) == 64:
        n = _pub_numbers()
        z = int.from_bytes(hashlib.sha256(f"{h}.{p}".encode()).digest(), "big")
        v = ecdsa_edu.verify(z, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"), n.x, n.y)
        trace.step(f"Verify ES256 signature (kid={_kid})", status="pass" if v.ok else "fail", layer="L1",
                   data=[("signing input", "b64url(header) + '.' + b64url(payload)"),
                         ("issuer public key Q.x", trace.short(f"{n.x:064x}")),
                         ("issuer public key Q.y", trace.short(f"{n.y:064x}"))],
                   math=v.lines(),
                   explain="If any byte of the header or payload changed, z changes and the recomputed x no "
                           "longer equals r." if v.ok else
                           "The payload no longer matches the signature: it was modified after signing.")
    try:
        claims = jwt.decode(token, _private_key.public_key(), algorithms=["ES256"], audience=settings.jwt_audience,
                            issuer=settings.jwt_issuer, leeway=30,
                            options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud", "iss"]})
    except jwt.ExpiredSignatureError:
        trace.step("Validate claims", status="fail", checks=[(False, f"now < exp ({payload.get('exp')})")])
        raise TokenError("token expired")
    except jwt.InvalidTokenError as e:
        trace.step("Signature / claims rejected", status="fail", data=[("reason", str(e))])
        raise TokenError("invalid token")

    now = int(time.time())
    trace.step("Validate claims", status="pass", layer="L1",
               checks=[(True, f"iss == {settings.jwt_issuer}"), (True, f"aud contains {settings.jwt_audience}"),
                       (True, f"nbf {claims['nbf']} ≤ now {now} (±30 s leeway)"),
                       (True, f"now {now} < exp {claims['exp']}  ({claims['exp'] - now}s left)")])
    return claims


def new_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_refresh(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_family() -> uuid.UUID:
    return uuid.uuid4()

"""FIDO2 / WebAuthn helpers with trace output (FIDO2 deck, slides 3-9)."""
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from webauthn.helpers import (base64url_to_bytes, decode_credential_public_key, parse_authenticator_data,
                              parse_client_data_json)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from .. import trace
from ..config import settings
from . import ecdsa_edu


def _flags(ad) -> str:
    f = ad.flags
    return f"UP={int(f.up)} UV={int(f.uv)} BE={int(f.be)} BS={int(f.bs)} AT={int(f.at)} ED={int(f.ed)}"


def auth_data_bytes_step(raw: bytes, title: str) -> None:
    ad = parse_authenticator_data(raw)
    rp_hash = hashlib.sha256(settings.rp_id.encode()).digest()
    trace.step(title, lane="API", layer="L1", status="pass" if ad.rp_id_hash == rp_hash else "fail",
               bytes=[{"label": "rpIdHash (32)", "hex": raw[:32].hex(), "tone": "a"},
                      {"label": "flags (1)", "hex": raw[32:33].hex(), "tone": "b"},
                      {"label": "signCount (4)", "hex": raw[33:37].hex(), "tone": "c"}]
               + ([{"label": f"attested credential + COSE key ({len(raw) - 37})", "hex": raw[37:].hex()[:96],
                    "tone": "d"}] if len(raw) > 37 else []),
               data=[(f"SHA-256(\"{settings.rp_id}\")", trace.short(rp_hash.hex(), 14, 8)
                      + (" ✓ matches" if ad.rp_id_hash == rp_hash else " ✗ mismatch")),
                     (f"flags 0x{raw[32]:02x}", _flags(ad)), ("signCount", ad.sign_count)],
               explain="The authenticator scopes every key to the site's rpId. A phishing site would produce a "
                       "different rpIdHash, so its signatures are useless here.")


def client_data_step(raw: bytes, expected_type: str, expected_challenge: bytes) -> None:
    cd = parse_client_data_json(raw)
    trace.step("Decode clientDataJSON (written by the browser)", lane="API", layer="L1",
               status="pass" if cd.type == expected_type and cd.challenge == expected_challenge
               and cd.origin in settings.expected_origins else "fail",
               data=[("clientDataJSON", raw.decode(errors="replace")[:220]),
                     ("SHA-256(clientDataJSON)", trace.short(hashlib.sha256(raw).hexdigest(), 14, 8))],
               checks=[(cd.type == expected_type, f"type == {expected_type}"),
                       (cd.challenge == expected_challenge, "challenge == the one this server issued"),
                       (cd.origin in settings.expected_origins, f"origin {cd.origin} is allowed")])


def signature_math_step(credential: dict, public_key_cose: bytes) -> None:
    """Redo the assertion's ECDSA verification by hand for the trace panel."""
    if not trace.active():
        return
    try:
        resp = credential["response"]
        auth_data = base64url_to_bytes(resp["authenticatorData"])
        cdj = base64url_to_bytes(resp["clientDataJSON"])
        sig = base64url_to_bytes(resp["signature"])
        key = decode_credential_public_key(public_key_cose)
        if getattr(key, "alg", None) != COSEAlgorithmIdentifier.ECDSA_SHA_256:
            trace.step("Signature algorithm", status="info", data=[("alg", str(getattr(key, "alg", "?")))])
            return
        r, s = decode_dss_signature(sig)
        msg = auth_data + hashlib.sha256(cdj).digest()
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        qx, qy = int.from_bytes(key.x, "big"), int.from_bytes(key.y, "big")
        v = ecdsa_edu.verify(z, r, s, qx, qy)
        trace.step("Verify the device's ECDSA P-256 signature", lane="API", layer="L1",
                   status="pass" if v.ok else "fail",
                   data=[("signed message", f"authenticatorData ({len(auth_data)} B) ‖ SHA-256(clientDataJSON) (32 B)"),
                         ("signature (DER)", trace.short(sig.hex(), 16, 8)),
                         ("stored public key Q.x", trace.short(key.x.hex())),
                         ("stored public key Q.y", trace.short(key.y.hex()))],
                   math=v.lines(),
                   explain="Only the holder of the private key inside the authenticator could produce (r, s) for "
                           "this exact challenge. The server holds nothing secret for passkeys.")
    except Exception as e:  # trace is best effort; the real check is py_webauthn's
        trace.step("Signature math unavailable", status="info", data=[("reason", str(e))])


def options_step(title: str, options_json: str) -> None:
    opts = json.loads(options_json)
    trace.step(title, lane="API", layer="L1", status="info",
               data=[("challenge (32 B random)", opts.get("challenge")), ("rpId", opts.get("rpId") or settings.rp_id),
                     ("userVerification", opts.get("userVerification")
                      or opts.get("authenticatorSelection", {}).get("userVerification")),
                     ("options", options_json[:400])],
               explain="The challenge is single-use and short-lived, so a captured response can't be replayed.")

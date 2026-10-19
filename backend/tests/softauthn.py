"""A minimal software FIDO2 authenticator for tests (ES256, attestation "none")."""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import encode_cbor


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, origin: str = "http://localhost:8080", rp_id: str = "localhost"):
        self.origin, self.rp_id = origin, rp_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def _rp_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def register(self, options: dict) -> dict:
        n = self.key.public_key().public_numbers()
        cose = encode_cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        auth_data = (self._rp_hash() + bytes([0x45]) + self.counter.to_bytes(4, "big") + bytes(16)
                     + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(self._client_data("webauthn.create", options["challenge"])),
                             "attestationObject": b64u(att), "transports": ["internal"]}}

    def assert_(self, options: dict, origin: str | None = None, tamper_challenge: bool = False) -> dict:
        self.counter += 1
        challenge = options["challenge"]
        if tamper_challenge:
            challenge = b64u(os.urandom(32))
        auth_data = self._rp_hash() + bytes([0x05]) + self.counter.to_bytes(4, "big")
        cdj = self._client_data("webauthn.get", challenge, origin)
        sig = self.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": None}}

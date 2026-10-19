"""Educational ECDSA P-256 verifier.

The authoritative checks use `cryptography` / py_webauthn. This module redoes
the verification by hand so the trace panel can show w, u1, u2 and the final
comparison. Its answer is always compared with the real library's answer.
"""
from dataclasses import dataclass

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

Point = tuple[int, int] | None


def _add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k: int, p: Point) -> Point:
    result: Point = None
    while k:
        if k & 1:
            result = _add(result, p)
        p = _add(p, p)
        k >>= 1
    return result


@dataclass
class Verification:
    ok: bool
    z: int
    w: int
    u1: int
    u2: int
    x: int
    r: int
    s: int

    def lines(self) -> list[str]:
        h = lambda v: f"{v:064x}"[:14] + "…" + f"{v:064x}"[-8:]
        return [
            f"z  = SHA-256(message) as integer   = {h(self.z)}",
            f"w  = s⁻¹ mod n                      = {h(self.w)}",
            f"u₁ = z·w mod n                      = {h(self.u1)}",
            f"u₂ = r·w mod n                      = {h(self.u2)}",
            f"X  = u₁·G + u₂·Q  →  x mod n        = {h(self.x)}",
            f"r  (from the signature)             = {h(self.r)}",
            f"x mod n == r  →  {'✓ signature valid' if self.ok else '✗ signature INVALID'}",
        ]


def verify(z: int, r: int, s: int, qx: int, qy: int) -> Verification:
    if not (0 < r < N and 0 < s < N):
        return Verification(False, z, 0, 0, 0, 0, r, s)
    w = pow(s, -1, N)
    u1, u2 = z * w % N, r * w % N
    pt = _add(_mul(u1, G), _mul(u2, (qx, qy)))
    x = pt[0] % N if pt else 0
    return Verification(x == r, z, w, u1, u2, x, r, s)

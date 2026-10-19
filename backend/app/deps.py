"""Request authentication and authorization (Lecture 2 pipeline, steps 1-5)."""
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from . import audit, db, lab, trace
from .security import sessions, tokens


@dataclass
class Principal:
    id: str
    name: str
    role: str
    scopes: set[str]
    amr: list[str]
    jti: str
    exp: int
    sid: str | None = None

    def actor(self) -> dict:
        return {"id": self.id, "name": self.name, "role": self.role}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def deny(request: Request, status: int, message: str, *, action: str, principal: Principal | None = None,
         detail: dict | None = None) -> HTTPException:
    audit.record(action, "denied", status_code=status, actor=principal.actor() if principal else None,
                 request_id=request.state.request_id, ip=client_ip(request), detail=detail)
    return HTTPException(status, message)


def current_principal(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme != "Bearer" or not token:
        trace.step("Extract bearer token", status="fail", explain="No `Authorization: Bearer <token>` header.")
        raise deny(request, 401, "Sign in to continue.", action="auth.token")
    trace.step("Extract bearer token", status="pass",
               data=[("header", f"Authorization: Bearer {trace.short(token, 16, 8)}")])
    try:
        claims = tokens.verify_access_token(token, verify_signature=lab.enabled("jwt_verification"))
    except tokens.TokenError as e:
        raise deny(request, 401, "Your session is no longer valid. Please sign in again.", action="auth.token",
                   detail={"reason": str(e)})

    with db.session() as conn:
        revoked = conn.execute("SELECT 1 FROM revoked_jti WHERE jti = %s", (claims.get("jti"),)).fetchone()
    trace.step("Check token revocation list", status="fail" if revoked else "pass",
               checks=[(not revoked, f"jti {claims.get('jti')} not revoked by a logout")])
    if revoked:
        raise deny(request, 401, "You have signed out. Please sign in again.", action="auth.token",
                   detail={"reason": "revoked"})

    # W13: the server-side session must still be alive (not idle too long, not past its lifetime).
    # Checked in its own transaction so an expiry is committed before the 401 is raised.
    with db.session() as conn:
        ok, code, msg = sessions.check(conn, claims.get("sid"))
    if not ok:
        audit.record("session.expired", code, status_code=401, request_id=request.state.request_id,
                     ip=client_ip(request), actor={"id": claims.get("sub"), "name": claims.get("name"),
                                                   "role": claims.get("role")})
        raise HTTPException(401, {"detail": msg, "code": code})

    return Principal(id=claims["sub"], name=claims.get("name", "?"), role=claims.get("role", "customer"),
                     scopes=set(str(claims.get("scope", "")).split()), amr=list(claims.get("amr", [])),
                     jti=claims.get("jti", ""), exp=int(claims.get("exp", 0)), sid=claims.get("sid"))


def require_scope(scope: str):
    def check(request: Request, p: Principal = Depends(current_principal)) -> Principal:
        ok = scope in p.scopes
        trace.step(f"Authorize: scope {scope}", layer="L2", status="pass" if ok else "fail",
                   checks=[(ok, f"'{scope}' ∈ token scope [{' '.join(sorted(p.scopes))}]")],
                   explain=None if ok else "Authenticated but not permitted: 403, not 401.")
        if not ok:
            raise deny(request, 403, "Your account can't do that.", action="authz.scope", principal=p,
                       detail={"required": scope})
        return p
    return check


def require_role(role: str):
    def check(request: Request, p: Principal = Depends(current_principal)) -> Principal:
        if not lab.enabled("rbac"):
            trace.step("Role check skipped (LAB: W9 off)", layer="L2", status="warn",
                       explain="Any signed-in user can reach this privileged endpoint.")
            return p
        ok = p.role == role
        trace.step(f"Authorize: role {role}", layer="L2", status="pass" if ok else "fail",
                   checks=[(ok, f"token role '{p.role}' == '{role}'")])
        if not ok:
            raise deny(request, 403, "This area is restricted to the audit team.", action="authz.role",
                       principal=p, detail={"required": role})
        return p
    return check

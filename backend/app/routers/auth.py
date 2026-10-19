import datetime as dt
import uuid

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .. import audit, db, lab, trace
from ..config import settings
from ..deps import Principal, client_ip, current_principal
from ..schemas import LoginIn, LogoutIn, RegisterIn
from ..security import crypto, passwords, ratelimit, sessions, tokens

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE = "sw_refresh"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _set_refresh_cookie(response: Response, raw: str) -> None:
    response.set_cookie(COOKIE, raw, max_age=settings.refresh_ttl_seconds, httponly=True, samesite="strict",
                        secure=settings.cookie_secure, path="/api/auth")


def _start_session(conn: psycopg.Connection, user: dict, response: Response, amr: list[str],
                   family=None, request: Request | None = None) -> dict:
    # A new sign-in opens a server-side session (W13); a refresh keeps the same one.
    if family is None:
        family = tokens.new_family()
        sessions.open_session(conn, family, user["id"], client_ip(request) if request else None,
                              request.headers.get("user-agent") if request else None)
    access, claims = tokens.issue_access_token(user, amr, sid=str(family))
    raw, digest = tokens.new_refresh_token()
    conn.execute("INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at) VALUES (%s, %s, %s, %s)",
                 (user["id"], digest, family, _now() + dt.timedelta(seconds=settings.refresh_ttl_seconds)))
    _set_refresh_cookie(response, raw)
    trace.step("Issue refresh token (HttpOnly cookie)", layer="L1", status="info",
               data=[("cookie", f"{COOKIE}; HttpOnly; SameSite=Strict; Path=/api/auth"),
                     ("stored in DB", f"SHA-256(token) = {trace.short(digest, 12, 6)}"),
                     ("lifetime", "7 days, rotated on every use")],
               explain="JavaScript can't read the cookie (HttpOnly) and other sites can't send it (SameSite). "
                       "The access token lives only in memory.")
    return {"access_token": access, "expires_in": settings.access_ttl_seconds,
            "user": {"id": str(user["id"]), "username": user["username"],
                     "full_name": crypto.reveal(user["full_name"], f"users.full_name:{user['id']}"),
                     "role": user["role"]}}


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response):
    rid, ip = request.state.request_id, client_ip(request)
    problems = passwords.policy_problems(body.password, body.username)
    trace.step("Password policy", layer="L2", status="fail" if problems else "pass",
               checks=[(len(body.password) >= 10, "at least 10 characters"),
                       (body.password.lower() not in passwords.COMMON, "not in the common-password list"),
                       (body.username not in body.password.lower(), "does not contain the username")])
    if problems:
        raise HTTPException(422, " ".join(problems))
    pw_hash = passwords.hash_password(body.password, secure=lab.enabled("argon2"))
    with db.session() as conn:
        try:
            with conn.transaction():
                # W12: the id is generated here so the name's AAD can bind it to this row.
                uid = uuid.uuid4()
                user = conn.execute(
                    "INSERT INTO users (id, username, full_name, password_hash) VALUES (%s, %s, %s, %s) "
                    "RETURNING id, username, role",
                    (uid, body.username, crypto.encrypt(body.full_name, f"users.full_name:{uid}"), pw_hash)).fetchone()
                user = {**user, "full_name": body.full_name}  # the response carries the name as typed
        except psycopg.errors.UniqueViolation:
            audit.record("auth.register", "rejected", status_code=409, request_id=rid, ip=ip,
                         detail={"username": body.username, "reason": "taken"})
            raise HTTPException(409, "That username is taken. Try another one.")
        # Open the wallet as the new user, so the RLS insert policy
        # (user_id = app_uid() AND balance = 0) is what allows it.
        conn.execute("SELECT set_config('app.user_id', %s, true), set_config('app.role', 'customer', true)",
                     (str(user["id"]),))
        conn.execute("INSERT INTO wallets (user_id) VALUES (%s)", (user["id"],))
        trace.step("Open wallet under RLS insert policy", lane="Database", layer="L3", status="pass",
                   data=[("policy", "wallets_open: WITH CHECK (user_id = app_uid() AND balance = 0)")],
                   explain="A client can't open a wallet for someone else or with a starting balance.")
        result = _start_session(conn, user, response, ["pwd"], request=request)
    audit.record("auth.register", "success", status_code=201, request_id=rid, ip=ip,
                 actor={"id": str(user["id"]), "name": user["username"], "role": "customer"})
    return result


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    rid, ip = request.state.request_id, client_ip(request)
    throttle = lab.enabled("login_throttle")

    if throttle:
        allowed, count, retry = ratelimit.hit(f"login:{ip}", settings.login_ip_limit_per_min)
        trace.step("Rate limit by client IP", layer="L1", status="pass" if allowed else "fail",
                   checks=[(allowed, f"{ip}: {count} / {settings.login_ip_limit_per_min} attempts this minute")])
        if not allowed:
            audit.record("auth.login", "throttled", status_code=429, request_id=rid, ip=ip,
                         detail={"username": body.username})
            raise HTTPException(429, "Too many sign-in attempts. Wait a minute and try again.",
                                headers={"Retry-After": str(int(retry) + 1)})
    else:
        trace.step("Login throttling skipped (LAB: W3 off)", status="warn",
                   explain="Unlimited guesses: a password list can be tried against any account.")

    with db.session() as conn:
        user = conn.execute("SELECT id, username, full_name, role, password_hash, failed_logins, locked_until "
                            "FROM users WHERE username = %s AND role <> 'system'", (body.username,)).fetchone()
        now = _now()
        if throttle and user and user["locked_until"] and user["locked_until"] > now:
            wait = int((user["locked_until"] - now).total_seconds()) + 1
            trace.step("Account lockout", status="fail",
                       checks=[(False, f"locked for another {wait}s after {user['failed_logins']} failed attempts")],
                       explain="Even the right password is refused while locked, so guessing can't continue.")
            audit.record("auth.login", "locked", status_code=429, request_id=rid, ip=ip,
                         actor={"id": str(user["id"]), "name": user["username"], "role": user["role"]})
            raise HTTPException(429, f"Too many failed attempts. Try again in {wait} seconds.",
                                headers={"Retry-After": str(wait)})
        if throttle and user:
            trace.step("Account lockout", status="pass",
                       checks=[(True, f"not locked ({user['failed_logins']} recent failures, lock at "
                                      f"{settings.lockout_threshold})")])

        ok = passwords.verify_password(user["password_hash"] if user else None, body.password)
        if not ok:
            if user:
                fails = user["failed_logins"] + 1
                lock = ratelimit.lockout_seconds(fails, settings.lockout_threshold) if throttle else 0
                conn.execute("UPDATE users SET failed_logins = %s, locked_until = %s WHERE id = %s",
                             (fails, now + dt.timedelta(seconds=lock) if lock else None, user["id"]))
                if lock:
                    trace.step("Lock account", status="warn",
                               data=[("failed attempts", fails), ("locked for", f"{lock}s (doubles each time)")])
        else:
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (user["id"],))
            result = _start_session(conn, user, response, ["pwd"], request=request)
    # Raised after the session commits, so the failure counter above is persisted.
    if not ok:
        audit.record("auth.login", "failed", status_code=401, request_id=rid, ip=ip,
                     detail={"username": body.username})
        raise HTTPException(401, "Incorrect username or password.")  # same message whether or not the user exists
    audit.record("auth.login", "success", status_code=200, request_id=rid, ip=ip,
                 actor={"id": str(user["id"]), "name": user["username"], "role": user["role"]})
    return result


@router.post("/refresh")
def refresh(request: Request, response: Response):
    # A custom header can't be added by a cross-site form post: CSRF defence on top of SameSite.
    if request.headers.get("x-requested-with") != "securewallet":
        raise HTTPException(403, "Missing request header.")
    raw = request.cookies.get(COOKIE)
    if not raw:
        raise HTTPException(401, "Please sign in.")
    digest = tokens.hash_refresh(raw)
    result, reused, idle = None, None, None
    with db.session() as conn:
        row = conn.execute("SELECT r.*, u.username, u.full_name, u.role FROM refresh_tokens r "
                           "JOIN users u ON u.id = r.user_id WHERE r.token_hash = %s FOR UPDATE OF r",
                           (digest,)).fetchone()
        if row and row["expires_at"] >= _now():
            if row["revoked_at"]:
                # A rotated token came back: someone else has a copy. Kill the whole family.
                conn.execute("UPDATE refresh_tokens SET revoked_at = now() "
                             "WHERE family = %s AND revoked_at IS NULL", (row["family"],))
                reused = row
            else:
                # W13: an idle or expired session can't be revived by refreshing it.
                ok, code, msg = sessions.check(conn, str(row["family"]), touch=False)
                if not ok:
                    idle = (code, msg, row)
            if not row["revoked_at"] and not idle:
                conn.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE id = %s", (row["id"],))
                user = {"id": row["user_id"], "username": row["username"], "full_name": row["full_name"],
                        "role": row["role"]}
                trace.step("Rotate refresh token", layer="L1", status="pass",
                           explain="The old token is revoked. If it is ever presented again, the whole session "
                                   "family is revoked because that means it was stolen.")
                result = _start_session(conn, user, response, ["pwd"], family=row["family"])
    if result:
        return result
    if idle:
        code, msg, row = idle
        audit.record("session.expired", code, status_code=401, request_id=request.state.request_id,
                     ip=client_ip(request), actor={"id": str(row["user_id"]), "name": row["username"],
                                                   "role": row["role"]})
        ended = JSONResponse({"detail": msg, "code": code}, status_code=401)
        ended.delete_cookie(COOKIE, path="/api/auth")
        return ended
    if reused:
        audit.record("auth.refresh", "reuse_detected", status_code=401, request_id=request.state.request_id,
                     ip=client_ip(request), actor={"id": str(reused["user_id"]), "name": reused["username"],
                                                   "role": reused["role"]})
    ended = JSONResponse({"detail": "Your session has ended. Please sign in again."}, status_code=401)
    ended.delete_cookie(COOKIE, path="/api/auth")
    return ended


@router.post("/logout")
def logout(body: LogoutIn, request: Request, response: Response, p: Principal = Depends(current_principal)):
    raw = request.cookies.get(COOKIE)
    with db.session(p.id, p.role) as conn:
        conn.execute("INSERT INTO revoked_jti (jti, expires_at) VALUES (%s, to_timestamp(%s)) ON CONFLICT DO NOTHING",
                     (p.jti, p.exp))
        if body.everywhere:
            conn.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                         (p.id,))
            sessions.end(conn, user_id=p.id, reason="signed out everywhere")
        else:
            if raw:
                conn.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = %s AND user_id = %s",
                             (tokens.hash_refresh(raw), p.id))
            sessions.end(conn, sid=p.sid, reason="signed out")
    trace.step("Revoke session", layer="L1", status="pass",
               data=[("access token jti", f"{p.jti} → revoked_jti"),
                     ("refresh tokens", "all devices" if body.everywhere else "this device")],
               explain="A copy of this access token is now rejected even before it expires.")
    response.delete_cookie(COOKIE, path="/api/auth")
    audit.record("auth.logout", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request), detail={"everywhere": body.everywhere})
    return {"ok": True}


@router.post("/heartbeat")
def heartbeat(p: Principal = Depends(current_principal)):
    """Called by the browser while the user is active; current_principal already refreshed last_seen_at."""
    return {"idle_seconds": sessions.idle_seconds(), "sid": p.sid}


@router.get("/jwks")
def jwks():
    return tokens.jwks()

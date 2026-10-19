"""W11: transaction PIN. Set or change it here; `enforce()` checks it on every transfer."""
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from .. import audit, db, lab, trace
from ..config import settings
from ..deps import Principal, client_ip, require_scope
from ..schemas import TpinSetIn
from ..security import passwords, ratelimit, tpin

router = APIRouter(prefix="/api/tpin", tags=["tpin"])


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@router.post("")
def set_tpin(body: TpinSetIn, request: Request, p: Principal = Depends(require_scope("transfer:write"))):
    rid, ip = request.state.request_id, client_ip(request)
    throttle = lab.enabled("login_throttle")
    with db.session(p.id, p.role) as conn:
        user = conn.execute("SELECT password_hash, failed_logins, locked_until, tpin_hash IS NOT NULL AS had_pin "
                            "FROM users WHERE id = %s", (p.id,)).fetchone()
        now = _now()
        locked = throttle and user and user["locked_until"] and user["locked_until"] > now
        if locked:
            wait = int((user["locked_until"] - now).total_seconds()) + 1
            trace.step("Account lockout", status="fail", checks=[(False, f"locked for another {wait}s")])
            ok = False
        else:
            # Re-authenticate: a stolen session alone must not be able to choose the PIN.
            ok = bool(user) and passwords.verify_password(user["password_hash"], body.password)
            if user and not ok:
                # Shares the login failure counter, so this endpoint can't be used to guess the password.
                fails = user["failed_logins"] + 1
                lock = ratelimit.lockout_seconds(fails, settings.lockout_threshold) if throttle else 0
                conn.execute("UPDATE users SET failed_logins = %s, locked_until = %s WHERE id = %s",
                             (fails, now + dt.timedelta(seconds=lock) if lock else None, p.id))
    # Raised after the session commits, so the failure counter above is persisted.
    if locked:
        audit.record("tpin.set", "locked", status_code=429, actor=p.actor(), request_id=rid, ip=ip)
        raise HTTPException(429, f"Too many failed attempts. Try again in {wait} seconds.",
                            headers={"Retry-After": str(wait)})
    if not ok:
        audit.record("tpin.set", "denied", status_code=403, actor=p.actor(), request_id=rid, ip=ip,
                     detail={"reason": "wrong password"})
        raise HTTPException(403, "Your password is incorrect.")

    problems = tpin.weak_pin_problems(body.new_pin)
    trace.step("Transaction PIN policy", layer="L2", status="fail" if problems else "pass",
               checks=tpin.pin_checks(body.new_pin))
    if problems:
        audit.record("tpin.set", "rejected", status_code=422, actor=p.actor(), request_id=rid, ip=ip,
                     detail={"reason": "weak pin"})
        raise HTTPException(422, " ".join(problems))

    pin_hash = tpin.hash_tpin(body.new_pin)
    with db.session(p.id, p.role) as conn:
        conn.execute("UPDATE users SET tpin_hash = %s, tpin_set_at = now(), tpin_failed = 0, "
                     "tpin_locked_until = NULL, failed_logins = 0 WHERE id = %s", (pin_hash, p.id))
    audit.record("tpin.set", "success", status_code=200, actor=p.actor(), request_id=rid, ip=ip,
                 detail={"changed": user["had_pin"]})
    return {"ok": True, "has_tpin": True, "changed": user["had_pin"]}


def _deny(status: int, code: str, detail: str, **extra) -> JSONResponse:
    headers = {"Retry-After": str(extra["retry_after"])} if "retry_after" in extra else None
    return JSONResponse({"detail": detail, "code": code, **extra}, status_code=status, headers=headers)


def enforce(p: Principal, pin: str | None, rid: str, ip: str, *, action: str = "transfer.create",
            doing: str = "sending money", to_do: str = "to send money") -> JSONResponse | None:
    """Check the PIN for a transfer (or another PIN-gated action, e.g. adding a beneficiary).
    Returns an error response, or None to proceed. All actions share one wrong-PIN counter and lock.

    Runs in its own DB transaction that commits before the caller responds, so a
    wrong-PIN counter or a lock is persisted even though the transfer is refused.
    """
    if not lab.enabled("tpin"):
        trace.step("Transaction PIN skipped (LAB: W11 off)", layer="L1", status="warn",
                   explain="Anyone holding a session token can move money without knowing the PIN.")
        return None

    denied = None
    with db.session(p.id, p.role) as conn:
        user = conn.execute("SELECT tpin_hash, tpin_failed, tpin_locked_until FROM users WHERE id = %s",
                            (p.id,)).fetchone()
        now = _now()
        if not user or not user["tpin_hash"]:
            trace.step("Transaction PIN", layer="L1", status="fail", checks=[(False, "a transaction PIN is set")],
                       explain="No PIN on this account yet, so no transfer can be authorised.")
            audit.record(action, "tpin_required", status_code=403, actor=p.actor(), request_id=rid, ip=ip)
            return _deny(403, "tpin_required", f"Set a transaction PIN in Security before {doing}.")

        if user["tpin_locked_until"] and user["tpin_locked_until"] > now:
            wait = int((user["tpin_locked_until"] - now).total_seconds()) + 1
            trace.step("Transaction PIN lock", layer="L1", status="fail",
                       checks=[(False, f"locked for another {wait}s after {settings.tpin_max_failures} wrong PINs")],
                       explain="Even the right PIN is refused while locked, so the 1-in-a-million guess can't go on.")
            audit.record(action, "tpin_locked", status_code=423, actor=p.actor(), request_id=rid, ip=ip)
            return _deny(423, "tpin_locked", f"Too many wrong PINs. Transfers are locked for {wait} seconds.",
                         retry_after=wait)

        if not pin:
            trace.step("Transaction PIN", layer="L1", status="fail", checks=[(False, "PIN present in the request")])
            audit.record(action, "tpin_missing", status_code=403, actor=p.actor(), request_id=rid, ip=ip)
            return _deny(403, "tpin_missing", f"Enter your transaction PIN {to_do}.")

        if tpin.verify_tpin(user["tpin_hash"], pin):
            # Only write when there is something to reset: keeps parallel transfers off the users row lock.
            conn.execute("UPDATE users SET tpin_failed = 0, tpin_locked_until = NULL "
                         "WHERE id = %s AND (tpin_failed <> 0 OR tpin_locked_until IS NOT NULL)", (p.id,))
            return None

        # Atomic increment, so parallel wrong guesses each count.
        fails = conn.execute("UPDATE users SET tpin_failed = tpin_failed + 1 WHERE id = %s RETURNING tpin_failed",
                             (p.id,)).fetchone()["tpin_failed"]
        left = settings.tpin_max_failures - fails
        if left <= 0:
            conn.execute("UPDATE users SET tpin_failed = 0, tpin_locked_until = %s WHERE id = %s",
                         (now + dt.timedelta(seconds=settings.tpin_lock_seconds), p.id))
            trace.step("Lock transfers", layer="L1", status="warn",
                       data=[("wrong PINs", fails), ("locked for", f"{settings.tpin_lock_seconds}s")])
            denied = ("tpin_locked", 423, f"Too many wrong PINs. Transfers are locked for "
                                          f"{settings.tpin_lock_seconds // 60} minutes.")
        else:
            trace.step("Count the wrong PIN", layer="L1", status="warn",
                       data=[("wrong PINs", f"{fails} of {settings.tpin_max_failures}")])
            denied = ("tpin_wrong", 403, f"Incorrect transaction PIN. {left} attempt{'s' if left != 1 else ''} left.")
    # Returned after the session commits, so the counter above is persisted.
    code, status, detail = denied
    audit.record(action, code, status_code=status, actor=p.actor(), request_id=rid, ip=ip,
                 detail={"failures": fails})
    if status == 423:
        return _deny(423, code, detail, retry_after=settings.tpin_lock_seconds)
    return _deny(403, code, detail, attempts_left=left)

"""W13: server-side sessions with an inactivity (idle) timeout and an absolute lifetime.

Each sign-in creates one `sessions` row (its id = the refresh-token family and the
`sid` claim in every access token). The server, not the browser, decides when a
session has been idle too long: a client-side timer alone could simply be skipped.
"""
import datetime as dt

import psycopg

from .. import db, lab, trace
from ..config import settings

# last_seen_at is not rewritten on every request: at most every 15 s, sooner for short demo limits.
TOUCH_MAX = 15


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def idle_seconds() -> int:
    """The configured idle limit; in demo mode the lab may shorten it for a live demonstration."""
    if settings.demo_mode and db.app_pool is not None:
        with db.app_pool.connection() as conn:
            row = conn.execute("SELECT value FROM lab_settings WHERE name = 'session_idle_seconds'").fetchone()
        if row and row["value"].isdigit():
            return int(row["value"])
    return settings.session_idle_seconds


def open_session(conn: psycopg.Connection, sid, user_id, ip: str | None, user_agent: str | None) -> None:
    conn.execute("INSERT INTO sessions (id, user_id, absolute_expires_at, ip, user_agent) VALUES (%s, %s, %s, %s, %s)",
                 (sid, user_id, _now() + dt.timedelta(seconds=settings.session_absolute_seconds), ip,
                  (user_agent or "")[:200]))
    trace.step("Open server-side session", lane="Database", layer="L1", status="info",
               data=[("session id (sid)", str(sid)), ("idle limit", f"{idle_seconds()} s of no activity"),
                     ("absolute limit", f"{settings.session_absolute_seconds // 3600} h")],
               explain="The session lives on the server, so the server can end it after inactivity even if the "
                       "browser tab is left open.")


def check(conn: psycopg.Connection, sid: str | None, *, touch: bool = True) -> tuple[bool, str | None, str]:
    """Return (ok, code, message). Marks the session revoked when it has expired."""
    if not sid:
        trace.step("Check server-side session", status="fail", data=[("sid", "missing from token")])
        return False, "session_expired", "Your session has ended. Please sign in again."
    row = conn.execute("SELECT * FROM sessions WHERE id = %s", (sid,)).fetchone()
    now = _now()
    if not row or row["revoked_at"]:
        trace.step("Check server-side session", status="fail",
                   data=[("sid", sid), ("state", f"ended ({row['revoke_reason']})" if row else "unknown")])
        return False, "session_expired", "Your session has ended. Please sign in again."

    limit = idle_seconds()
    idle = (now - row["last_seen_at"]).total_seconds()
    enforce = lab.enabled("session_timeout")
    if now > row["absolute_expires_at"]:
        code, reason = "session_expired", "absolute lifetime reached"
    elif enforce and idle > limit:
        code, reason = "session_idle", f"idle {int(idle)} s > limit {limit} s"
    else:
        code = reason = None

    if code:
        conn.execute("UPDATE sessions SET revoked_at = now(), revoke_reason = %s WHERE id = %s", (reason, sid))
        conn.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE family = %s AND revoked_at IS NULL", (sid,))
        trace.step("Check server-side session", layer="L1", status="fail",
                   checks=[(False, f"last activity {int(idle)} s ago; limit {limit} s")],
                   explain="The session is ended on the server and its refresh tokens are revoked, so it can't be "
                           "revived by refreshing either.")
        span = f"{limit} seconds" if limit < 60 else f"{round(limit / 60)} minute{'s' if round(limit / 60) != 1 else ''}"
        msg = (f"You were signed out after {span} of inactivity."
               if code == "session_idle" else "Your session has ended. Please sign in again.")
        return False, code, msg

    if not enforce:
        trace.step("Inactivity timeout skipped (LAB: W13 off)", layer="L1", status="warn",
                   data=[("idle for", f"{int(idle)} s")],
                   explain="An unattended, signed-in screen stays usable by whoever walks up to it.")
    else:
        trace.step("Check server-side session", layer="L1", status="pass",
                   checks=[(True, f"last activity {int(idle)} s ago, limit {limit} s ({int(limit - idle)} s left)"),
                           (True, f"absolute expiry {row['absolute_expires_at']:%H:%M} UTC not reached")])
    if touch and (now - row["last_seen_at"]).total_seconds() > min(TOUCH_MAX, limit / 5):
        conn.execute("UPDATE sessions SET last_seen_at = now() WHERE id = %s", (sid,))
    return True, None, ""


def end(conn: psycopg.Connection, *, sid: str | None = None, user_id: str | None = None, reason: str) -> None:
    if user_id:
        conn.execute("UPDATE sessions SET revoked_at = now(), revoke_reason = %s "
                     "WHERE user_id = %s AND revoked_at IS NULL", (reason, user_id))
    elif sid:
        conn.execute("UPDATE sessions SET revoked_at = now(), revoke_reason = %s "
                     "WHERE id = %s AND revoked_at IS NULL", (reason, sid))

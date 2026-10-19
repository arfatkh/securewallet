"""Vulnerability lab. Mounted only when DEMO_MODE=true."""
from fastapi import APIRouter, Depends, HTTPException, Request

from .. import audit, db, migrate
from ..deps import Principal, client_ip, current_principal
from ..lab import FLAGS
from ..schemas import FlagIn, LabSettingIn
from ..security import crypto, ratelimit

router = APIRouter(prefix="/api/lab", tags=["lab"])
NAMES = {f[0] for f in FLAGS}


@router.get("/flags")
def flags(p: Principal = Depends(current_principal)):
    with db.owner_conn() as conn:
        rows = conn.execute("SELECT name, enabled, weakness, title, description FROM lab_flags").fetchall()
    order = [f[0] for f in FLAGS]
    return {"items": sorted(rows, key=lambda r: order.index(r["name"]) if r["name"] in order else 99)}


@router.put("/flags/{name}")
def set_flag(name: str, body: FlagIn, request: Request, p: Principal = Depends(current_principal)):
    if name not in NAMES:
        raise HTTPException(404, "Unknown control.")
    with db.owner_conn() as conn, conn.transaction():
        conn.execute("UPDATE lab_flags SET enabled = %s WHERE name = %s", (body.enabled, name))
        # These two controls live in the database itself, so switching them is real DDL.
        if name == "rls":
            verb = "ENABLE" if body.enabled else "DISABLE"
            conn.execute(f"ALTER TABLE wallets {verb} ROW LEVEL SECURITY")
            conn.execute(f"ALTER TABLE transactions {verb} ROW LEVEL SECURITY")
        if name == "amount_validation":
            has = conn.execute("SELECT 1 FROM pg_constraint WHERE conname = 'amount_positive'").fetchone()
            if body.enabled and not has:
                conn.execute("ALTER TABLE transactions ADD CONSTRAINT amount_positive CHECK (amount > 0) NOT VALID")
            elif not body.enabled and has:
                conn.execute("ALTER TABLE transactions DROP CONSTRAINT amount_positive")
    if name == "login_throttle" and body.enabled:
        ratelimit.reset()
    audit.record("lab.toggle", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request), detail={"control": name, "enabled": body.enabled})
    return {"name": name, "enabled": body.enabled}


@router.put("/settings/{name}")
def set_setting(name: str, body: LabSettingIn, request: Request, p: Principal = Depends(current_principal)):
    """Demo tunable: a short inactivity limit so W13 can be shown live without waiting 5 minutes."""
    if name != "session_idle_seconds" or not body.value.isdigit() or not 15 <= int(body.value) <= 3600:
        raise HTTPException(422, "session_idle_seconds must be a whole number of seconds from 15 to 3600.")
    with db.owner_conn() as conn:
        conn.execute("INSERT INTO lab_settings (name, value) VALUES (%s, %s) "
                     "ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value", (name, body.value))
    audit.record("lab.setting", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request), detail={"setting": name, "value": body.value})
    return {"name": name, "value": body.value}


@router.get("/targets")
def targets(p: Principal = Depends(current_principal)):
    """Ids an attacker would otherwise have to guess or harvest. Demo convenience only."""
    with db.owner_conn() as conn:
        rows = conn.execute("SELECT u.id AS user_id, u.username, u.full_name, w.id AS wallet_id FROM users u "
                            "JOIN wallets w ON w.user_id = u.id WHERE u.role = 'customer' AND u.id <> %s "
                            "ORDER BY u.username", (p.id,)).fetchall()
    return {"items": [{**{k: str(v) for k, v in r.items()},
                       "full_name": crypto.reveal(r["full_name"], f"users.full_name:{r['user_id']}", quiet=True)}
                      for r in rows]}


@router.get("/users-table")
def users_table(p: Principal = Depends(current_principal)):
    """What an attacker sees if they dump the users table (W2 and W12 demos): values exactly as stored."""
    with db.owner_conn() as conn:
        rows = conn.execute("SELECT username, full_name, password_hash, created_at FROM users WHERE role <> 'system' "
                            "ORDER BY created_at DESC LIMIT 8").fetchall()
    return {"items": [{**r, "created_at": r["created_at"].isoformat()} for r in rows]}


@router.get("/raw-transactions")
def raw_transactions(p: Principal = Depends(current_principal)):
    """What a DBA or a stolen backup shows for transfer notes (W12 demo): values exactly as stored."""
    with db.owner_conn() as conn:
        rows = conn.execute("SELECT ref, note, amount, created_at FROM transactions "
                            "ORDER BY created_at DESC LIMIT 8").fetchall()
    return {"items": [{**r, "created_at": r["created_at"].isoformat()} for r in rows]}


@router.post("/reset")
def reset(request: Request, p: Principal = Depends(current_principal)):
    with db.owner_conn() as conn, conn.transaction():
        migrate.reset(conn)
    ratelimit.reset()
    audit.record("lab.reset", "success", status_code=200, actor=p.actor(), request_id=request.state.request_id,
                 ip=client_ip(request))
    return {"ok": True}

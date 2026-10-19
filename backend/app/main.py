import json
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import db, migrate, trace
from .config import settings
from .routers import auditing, auth, beneficiaries, lab, passkeys, tpin, transfers, wallet
from .security import crypto, tokens

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("securewallet")


@asynccontextmanager
async def lifespan(app: FastAPI):
    tokens.load_or_create_key()
    crypto.load_or_create_key()  # W12 data-encryption key; before migrate(), which seeds encrypted rows
    migrate.migrate()
    db.open_pools()
    log.info("SecureWallet API ready (demo mode %s)", "ON" if settings.demo_mode else "off")
    yield
    db.close_pools()


app = FastAPI(title="SecureWallet API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

for r in (auth.router, wallet.router, transfers.router, passkeys.router, auditing.router, tpin.router,
          beneficiaries.router):
    app.include_router(r)
if settings.demo_mode:
    app.include_router(lab.router)  # secure default: the lab does not exist outside demo mode


@app.middleware("http")
async def pipeline(request: Request, call_next):
    request.state.request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex[:16]
    tracing = settings.demo_mode and request.headers.get("x-security-trace") == "1"
    if tracing:
        trace.begin()
    try:
        response: Response = await call_next(request)
        if tracing and response.headers.get("content-type", "").startswith("application/json"):
            body = b"".join([chunk async for chunk in response.body_iterator])
            try:
                payload = json.loads(body) if body else {}
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                payload["_trace"] = trace.steps()
                headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
                response = JSONResponse(payload, status_code=response.status_code, headers=headers)
            else:
                response = Response(body, status_code=response.status_code, headers=dict(response.headers))
    finally:
        if tracing:
            trace.end()
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    body = exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}  # {"detail", "code"} stays flat
    return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Friendly first message; no echo of the submitted values (they may contain a password).
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(x) for x in first.get("loc", [])[1:]) or "request"
    msg = str(first.get("msg", "Invalid request")).removeprefix("Value error, ")
    trace.step("Schema validation (Pydantic, strict)", layer="L2", status="fail",
               data=[("field", field), ("problem", msg)],
               explain="Unknown fields are rejected and types are strict, so '100', 1.5 or an extra "
                       "'balance' field never reach business logic.")
    return JSONResponse({"detail": f"{field}: {msg}" if field != "request" else msg, "field": field},
                        status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error (request %s)", getattr(request.state, "request_id", "?"))
    # No stack traces or SQL leave the server.
    return JSONResponse({"detail": "Something went wrong on our side. Please try again.",
                         "request_id": getattr(request.state, "request_id", None)}, status_code=500)


@app.get("/api/health")
def health():
    try:
        with db.session() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:
        return JSONResponse({"status": "degraded"}, status_code=503)


@app.get("/api/config")
def config():
    from . import lab as lab_flags
    from .security import sessions
    return {"demo_available": settings.demo_mode, "rp_id": settings.rp_id,
            "session": {"idle_seconds": sessions.idle_seconds(), "absolute_seconds": settings.session_absolute_seconds,
                        "enforced": lab_flags.enabled("session_timeout")},
            "limits": {"max_transfer": settings.max_transfer, "stepup_amount": settings.stepup_amount,
                       "new_payee_amount": settings.new_payee_amount}}

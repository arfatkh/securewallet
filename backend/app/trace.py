"""Security trace collector.

When demo mode is on and a request carries `X-Security-Trace: 1`, each
security decision the backend makes is recorded as a step and returned under
`_trace`. Otherwise `step()` is a no-op, so nothing is collected or leaked.
"""
import contextvars
import time
from typing import Any

_current: contextvars.ContextVar["Trace | None"] = contextvars.ContextVar("trace", default=None)


class Trace:
    def __init__(self) -> None:
        self.t0 = time.perf_counter()
        self.steps: list[dict[str, Any]] = []


def begin() -> Trace:
    t = Trace()
    _current.set(t)
    return t


def end() -> None:
    _current.set(None)


def active() -> bool:
    return _current.get() is not None


def step(title: str, *, lane: str = "API", layer: str = "L1", status: str = "info",
         data: list[tuple[str, Any]] | None = None, math: list[str] | None = None,
         checks: list[tuple[bool, str]] | None = None, explain: str | None = None,
         **extra: Any) -> None:
    t = _current.get()
    if t is None:
        return
    s: dict[str, Any] = {
        "seq": len(t.steps) + 1,
        "t_ms": round((time.perf_counter() - t.t0) * 1000, 1),
        "lane": lane, "layer": layer, "title": title, "status": status,
    }
    if data:
        s["data"] = [[k, str(v)] for k, v in data]
    if math:
        s["math"] = math
    if checks:
        s["checks"] = [[bool(ok), text] for ok, text in checks]
    if explain:
        s["explain"] = explain
    s.update(extra)
    t.steps.append(s)


def steps() -> list[dict[str, Any]]:
    t = _current.get()
    return t.steps if t else []


def short(value: str | bytes, head: int = 10, tail: int = 6) -> str:
    """Truncate long hex/base64 for display; secrets are never passed in here."""
    if isinstance(value, bytes):
        value = value.hex()
    return value if len(value) <= head + tail + 1 else f"{value[:head]}…{value[-tail:]}"

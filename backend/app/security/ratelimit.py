"""W3: sliding-window limiter keyed by client IP.

Per-IP limits alone are bypassed by botnets (Lecture 1, slide 17), so login
also has a per-account lockout stored in the users table.
"""
import threading
import time
from collections import defaultdict, deque

_windows: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def hit(key: str, limit: int, window_s: float = 60.0) -> tuple[bool, int, float]:
    """Record one hit. Returns (allowed, count_in_window, retry_after_seconds)."""
    now = time.monotonic()
    with _lock:
        q = _windows[key]
        while q and now - q[0] > window_s:
            q.popleft()
        if len(q) >= limit:
            return False, len(q), window_s - (now - q[0])
        q.append(now)
        return True, len(q), 0.0


def reset() -> None:
    with _lock:
        _windows.clear()


def lockout_seconds(failed_logins: int, threshold: int) -> int:
    """5 failures → 60 s, then doubling per extra failure, capped at 15 minutes."""
    if failed_logins < threshold:
        return 0
    return min(60 * 2 ** (failed_logins - threshold), 900)

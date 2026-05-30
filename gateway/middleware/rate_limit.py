import time
import threading
from collections import defaultdict
from fastapi import HTTPException
from config import RATE_LIMITS, RATE_WINDOW_SECONDS

_lock = threading.Lock()
_request_log: dict = defaultdict(list)
_last_cleanup = time.time()
CLEANUP_INTERVAL = 120  # purge stale entries every 2 min


def _cleanup():
    """Remove entries older than the rate window."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    cutoff = now - RATE_WINDOW_SECONDS
    stale = [uid for uid, ts in _request_log.items() if not ts or ts[-1] < cutoff]
    for uid in stale:
        del _request_log[uid]


def check_rate_limit(user_id: str, role: str):
    now = time.time()
    window = RATE_WINDOW_SECONDS
    limit = RATE_LIMITS.get(role, 5)

    with _lock:
        _cleanup()
        timestamps = _request_log[user_id]
        recent = [t for t in timestamps if now - t < window]
        if len(recent) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Role '{role}' allows {limit} requests/minute. Try again later."
            )
        recent.append(now)
        _request_log[user_id] = recent


def get_request_count(user_id: str) -> int:
    now = time.time()
    with _lock:
        if user_id not in _request_log:
            return 0
        _request_log[user_id] = [t for t in _request_log[user_id] if now - t < RATE_WINDOW_SECONDS]
        return len(_request_log[user_id])

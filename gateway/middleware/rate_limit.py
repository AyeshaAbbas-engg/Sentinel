import time
from collections import defaultdict
from fastapi import HTTPException

RATE_LIMITS = {
    "admin": 60,
    "analyst": 20,
    "guest": 5
}

request_log: dict = defaultdict(list)


def check_rate_limit(user_id: str, role: str):
    now = time.time()
    window = 60
    timestamps = request_log[user_id]
    recent = [t for t in timestamps if now - t < window]
    limit = RATE_LIMITS.get(role, 5)
    if len(recent) >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Role '{role}' allows {limit} requests/minute. Try again later."
        )
    recent.append(now)
    request_log[user_id] = recent


def get_request_count(user_id: str) -> int:
    """Returns how many requests this user made in the last minute."""
    now = time.time()
    if user_id not in request_log:
        return 0
    request_log[user_id] = [t for t in request_log[user_id] if now - t < 60]
    return len(request_log[user_id])
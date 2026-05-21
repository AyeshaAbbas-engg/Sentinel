import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt

JWT_SECRET = "sentinel-super-secret-key-2026"
ALGORITHM = "HS256"
BASE_URL = "http://localhost:8000"


def make_token(user_id: str, role: str, expires_minutes: int = 60):
    payload = {
        "sub": user_id,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


@pytest.fixture
def admin_token():
    return make_token("u_admin001", "admin")

@pytest.fixture
def analyst_token():
    return make_token("u_analyst001", "analyst")

@pytest.fixture
def guest_token():
    return make_token("u_guest001", "guest")

@pytest.fixture
def expired_token():
    return make_token("u_test001", "guest", expires_minutes=-1)
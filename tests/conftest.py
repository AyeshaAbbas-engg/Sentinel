import os
import httpx
import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt

JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
BASE_URL = "http://localhost:8000"


def make_token(user_id: str, role: str, expires_minutes: int = 60):
    """Get ordinary test tokens from the gateway instead of copying its secret."""
    if expires_minutes == 60:
        with httpx.Client(timeout=10) as client:
            response = client.post(
                f"{BASE_URL}/token", json={"user_id": user_id, "role": role}
            )
        response.raise_for_status()
        return response.json()["access_token"]

    if not JWT_SECRET:
        pytest.skip("Expired-token test requires JWT_SECRET in the test environment")
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

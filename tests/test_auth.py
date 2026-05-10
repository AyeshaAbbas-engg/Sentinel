import httpx
import pytest
from conftest import BASE_URL, make_token

def test_no_token_returns_401():
    """Request with no token must be rejected"""
    with httpx.Client() as client:
        response = client.post(
            f"{BASE_URL}/chat",
            json={"prompt": "hello", "model": "phi3:mini"}
        )
    assert response.status_code == 401
    assert "Missing Authorization header" in response.json()["detail"]

def test_fake_token_returns_401():
    """Tampered/fake token must be rejected"""
    with httpx.Client() as client:
        response = client.post(
            f"{BASE_URL}/chat",
            json={"prompt": "hello", "model": "phi3:mini"},
            headers={"Authorization": "Bearer faketoken123"}
        )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.json()["detail"]

def test_expired_token_returns_401(expired_token):
    """Expired token must be rejected"""
    with httpx.Client() as client:
        response = client.post(
            f"{BASE_URL}/chat",
            json={"prompt": "hello", "model": "phi3:mini"},
            headers={"Authorization": f"Bearer {expired_token}"}
        )
    assert response.status_code == 401

def test_valid_admin_token_returns_200(admin_token):
    """Valid admin token must be accepted"""
    with httpx.Client(timeout=120) as client:
        response = client.post(
            f"{BASE_URL}/chat",
            json={"prompt": "Say hello.", "model": "phi3:mini"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "u_admin001"
    assert data["role"] == "admin"
    assert data["response"] != ""

def test_valid_guest_token_returns_200(guest_token):
    """Valid guest token must be accepted"""
    with httpx.Client(timeout=120) as client:
        response = client.post(
            f"{BASE_URL}/chat",
            json={"prompt": "Say hello.", "model": "phi3:mini"},
            headers={"Authorization": f"Bearer {guest_token}"}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "guest"
    assert data["user_id"] == "u_guest001"
def test_health_endpoint():
    """Health check must always return 200"""
    with httpx.Client() as client:
        response = client.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    
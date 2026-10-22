import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_success_form(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "TestAdmin123!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "super_admin"
    assert data["username"] == "admin"


@pytest.mark.asyncio
async def test_login_success_json(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login-json",
        json={"username": "engineer", "password": "TestEngineer123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "network_engineer"


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "WrongPassword999!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_current_user_me(client: AsyncClient, admin_token: str):
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["role"] == "super_admin"


@pytest.mark.asyncio
async def test_logout_creates_audit(client: AsyncClient, admin_token: str):
    response = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out"

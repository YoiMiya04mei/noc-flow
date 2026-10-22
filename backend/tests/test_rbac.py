import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_operator_cannot_create_device(client: AsyncClient, operator_token: str):
    response = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "forbidden-router.noc.local",
            "mgmt_ip": "10.0.0.99",
            "vendor": "Cisco",
        },
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auditor_cannot_add_prefix_allowlist(client: AsyncClient, auditor_token: str):
    response = await client.post(
        "/api/v1/admin/policies/prefixes",
        json={
            "prefix": "203.0.113.0/24",
            "description": "Auditor unauthorized test",
        },
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_engineer_can_create_device(client: AsyncClient, engineer_token: str):
    response = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "core-router-01.cgk.net",
            "mgmt_ip": "10.250.0.10",
            "vendor": "Juniper",
            "model": "MX960",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["hostname"] == "core-router-01.cgk.net"
    assert len(data["interfaces"]) == 3


@pytest.mark.asyncio
async def test_super_admin_can_add_prefix_allowlist(client: AsyncClient, admin_token: str):
    response = await client.post(
        "/api/v1/admin/policies/prefixes",
        json={
            "prefix": "198.51.100.0/24",
            "description": "Admin authorized prefix",
            "is_active": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["prefix"] == "198.51.100.0/24"


@pytest.mark.asyncio
async def test_auditor_can_read_audit_logs(client: AsyncClient, auditor_token: str):
    response = await client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoints(client: AsyncClient):
    res_health = await client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"
    assert res_health.json()["routing_execution_enabled"] is False

    res_ready = await client.get("/ready")
    assert res_ready.status_code == 200
    assert res_ready.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_collector_registration_and_health(
    client: AsyncClient, engineer_token: str
):
    create_res = await client.post(
        "/api/v1/collectors",
        json={
            "name": "Collector-Test-Cluster",
            "host": "127.0.0.1",
            "port": 2055,
            "collector_type": "netflow",
            "status": "active",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert create_res.status_code == 201
    col_id = create_res.json()["id"]

    health_res = await client.get(
        f"/api/v1/collectors/{col_id}/health",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert health_res.status_code == 200
    assert health_res.json()["health"] == "healthy"


@pytest.mark.asyncio
async def test_audit_trail_captures_events(client: AsyncClient, admin_token: str):
    # Perform an audited operation
    await client.post(
        "/api/v1/admin/policies/prefixes",
        json={"prefix": "192.0.2.0/24", "description": "Audit trail test prefix"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Query audit log
    audit_res = await client.get(
        "/api/v1/audit?action=ADD_PREFIX_ALLOWLIST",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_res.status_code == 200
    events = audit_res.json()
    assert len(events) >= 1
    assert events[0]["actor_username"] == "admin"
    assert events[0]["action"] == "ADD_PREFIX_ALLOWLIST"
    assert "192.0.2.0/24" in events[0]["details"]

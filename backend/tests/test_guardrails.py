import pytest
from httpx import AsyncClient
from app.core.config import settings


@pytest.mark.asyncio
async def test_guardrail_blocks_default_routes(client: AsyncClient, admin_token: str):
    # Reject 0.0.0.0/0
    res_ipv4 = await client.post(
        "/api/v1/admin/policies/prefixes",
        json={"prefix": "0.0.0.0/0", "description": "Illegal default route"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_ipv4.status_code == 422 # Pydantic validation error

    # Reject ::/0
    res_ipv6 = await client.post(
        "/api/v1/admin/policies/prefixes",
        json={"prefix": "::/0", "description": "Illegal IPv6 default route"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_ipv6.status_code == 422


@pytest.mark.asyncio
async def test_deny_by_default_blocks_unallowlisted_prefix(
    client: AsyncClient, engineer_token: str
):
    # Prefix 10.99.99.0/24 is not allowlisted
    response = await client.post(
        "/api/v1/change-requests",
        json={
            "target_peer": "198.51.100.1",
            "prefix": "10.99.99.0/24",
            "diff_payload": "set protocols bgp group transit neighbor 198.51.100.1 export reject",
            "justification": "Test change without allowlist",
            "rollback_instructions": "delete export",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert response.status_code == 400
    assert "GUARDRAIL REJECTION" in response.json()["detail"]


@pytest.mark.asyncio
async def test_dual_approval_and_execution_guardrail(
    client: AsyncClient, engineer_token: str, approver_token: str
):
    # 1. Engineer creates valid change request for allowlisted prefix 103.145.2.0/24
    create_res = await client.post(
        "/api/v1/change-requests",
        json={
            "target_peer": "198.51.100.1",
            "prefix": "103.145.2.0/24",
            "diff_payload": "set policy-options community AS4761_PREPEND members 4761:100",
            "justification": "Shift traffic to Indosat to decrease latency",
            "rollback_instructions": "delete policy-options community AS4761_PREPEND",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert create_res.status_code == 201
    change_id = create_res.json()["id"]

    # 2. Engineer attempts to approve own change request -> Rejected (Dual approval rule)
    self_approve_res = await client.post(
        f"/api/v1/change-requests/{change_id}/approve",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert self_approve_res.status_code == 403 or self_approve_res.status_code == 400

    # 3. Independent Approver approves
    approve_res = await client.post(
        f"/api/v1/change-requests/{change_id}/approve",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["execution_status"] == "approved"

    # 4. Attempt to execute -> CRITICAL GUARDRAIL TRIGGERED: ROUTING_EXECUTION_ENABLED is False
    assert settings.ROUTING_EXECUTION_ENABLED is False
    exec_res = await client.post(
        f"/api/v1/change-requests/{change_id}/execute",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert exec_res.status_code == 403
    assert "SAFETY GUARDRAIL ENFORCED" in exec_res.json()["detail"]
    assert "ROUTING_EXECUTION_ENABLED is FALSE" in exec_res.json()["detail"]

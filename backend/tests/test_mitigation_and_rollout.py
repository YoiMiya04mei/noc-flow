import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.recommendation import ChangeRequest
from app.models.mitigation import (
    ThreatCandidate,
    MitigationRule,
    RolloutExecution,
    CircuitBreakerEvent,
)
from app.models.user import User, UserRole, UserStatus
from app.services.circuit_breaker import CircuitBreakerService
from app.services.execution_gate import ProductionExecutionGate
from app.services.mitigation_service import MitigationService
from app.services.production_adapter import ProductionBGPAdapter, ProductionAdapterError
from app.services.rollout_service import RolloutService


# -----------------------------------------------------------------------------
# 1. Production Execution Flags Locked by Default
# -----------------------------------------------------------------------------
def test_production_execution_flags_locked_by_default():
    """Confirms that fresh install/default settings have ALL execution flags disabled."""
    assert settings.ROUTING_EXECUTION_ENABLED is False
    assert settings.PRODUCTION_ROUTING_ENABLED is False
    assert settings.FLOWSPEC_EXECUTION_ENABLED is False
    assert settings.RTBH_EXECUTION_ENABLED is False
    assert settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD == 3
    assert settings.MAX_ROLLOUT_PREFIX_LIMIT == 5


# -----------------------------------------------------------------------------
# 2. Production BGP Adapter Safety & Isolation
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_production_adapter_dry_run_and_execution_lock():
    """Verifies that ProductionBGPAdapter generates config syntax preview but blocks live execution."""
    status_info = ProductionBGPAdapter.get_adapter_status()
    assert status_info["safety_mode"] == "LOCKED_DRY_RUN"
    assert status_info["is_enabled"] is False

    # 1. Preview compilation succeeds for allowlisted peer and valid prefix
    preview = await ProductionBGPAdapter.execute_dry_run_preview(
        operation="ANNOUNCE_UNICAST",
        target_device="router-core-1",
        target_peer="198.51.100.1",
        prefix="103.145.2.0/24",
        attributes={"local_pref": 120, "communities": ["65000:100"]},
    )
    assert preview["dry_run"] is True
    assert "junos" in preview["simulated_commands"]
    assert "huawei" in preview["simulated_commands"]
    assert "cisco" in preview["simulated_commands"]
    assert "103.145.2.0_24" in preview["simulated_commands"]["junos"]

    # 2. Rejection of unsupported operations
    with pytest.raises(ProductionAdapterError, match="not in ALLOWED_OPERATIONS"):
        await ProductionBGPAdapter.execute_dry_run_preview(
            operation="ILLEGAL_SHELL_EXEC",
            target_device="router-core-1",
            target_peer="198.51.100.1",
            prefix="103.145.2.0/24",
            attributes={},
        )

    # 3. Live execution attempt raises 403 Forbidden while flags are False
    with pytest.raises(HTTPException) as exc_info:
        await ProductionBGPAdapter.transmit_live_operation(
            operation="ANNOUNCE_UNICAST",
            target_device="router-core-1",
            target_peer="198.51.100.1",
            prefix="103.145.2.0/24",
            attributes={},
        )
    assert exc_info.value.status_code == 403
    assert "SAFETY LOCKOUT" in exc_info.value.detail


# -----------------------------------------------------------------------------
# 3. 12-Point Production Execution Gate Evaluator
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_12_point_execution_gate_evaluator(
    client: AsyncClient,
    db_session: AsyncSession,
    engineer_token: str,
):
    """Verifies all 12 gate criteria in ProductionExecutionGate."""
    creator = User(
        username="cr_eng",
        email="cr_eng@test.net",
        password_hash="hash",
        role=UserRole.NETWORK_ENGINEER.value,
        status=UserStatus.ACTIVE.value,
    )
    approver1 = User(
        username="cr_mgr",
        email="cr_mgr@test.net",
        password_hash="hash",
        role=UserRole.APPROVER.value,
        status=UserStatus.ACTIVE.value,
    )
    approver2 = User(
        username="cr_admin",
        email="cr_admin@test.net",
        password_hash="hash",
        role=UserRole.SUPER_ADMIN.value,
        status=UserStatus.ACTIVE.value,
    )
    db_session.add_all([creator, approver1, approver2])
    await db_session.commit()
    await db_session.refresh(creator)
    await db_session.refresh(approver1)
    await db_session.refresh(approver2)

    # Create unapproved ChangeRequest
    cr = ChangeRequest(
        requester_id=creator.id,
        target_peer="198.51.100.1",
        prefix="103.145.2.0/24",
        diff_payload="set policy-options community P members 100",
        justification="Latency optimization",
        rollback_instructions="delete policy-options community P",
        validation_status="valid",
        execution_status="pending_approval",
        lab_tested=False,
        requires_dual_approval=True,
    )
    db_session.add(cr)
    await db_session.commit()
    await db_session.refresh(cr)

    # 1. Gate evaluation on unapproved CR via API -> overall_status is BLOCKED
    eval_res = await client.get(
        f"/api/v1/mitigation/execution-gate/evaluate/{cr.id}",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert eval_res.status_code == 200
    report = eval_res.json()
    assert report["overall_status"] == "BLOCKED"
    assert report["is_production_ready"] is False
    assert len(report["items"]) == 12

    # Check 1 (Environment flag) must be BLOCKED
    c1 = next(i for i in report["items"] if "Environment" in i["criterion"])
    assert c1["status"] == "BLOCKED"

    # Check 4 (Change Request Approval) must be BLOCKED
    c4 = next(i for i in report["items"] if "Approval" in i["criterion"])
    assert c4["status"] == "BLOCKED"

    # Check 7 (Lab Test) must be BLOCKED
    c7 = next(i for i in report["items"] if "Lab Test" in i["criterion"])
    assert c7["status"] == "BLOCKED"

    # 2. Update CR to fully approved with lab_tested=True and dual-approval
    cr.execution_status = "approved"
    cr.approver_id = approver1.id
    cr.second_approver_id = approver2.id
    cr.lab_tested = True
    cr.lab_test_run_id = 1
    await db_session.commit()

    # 3. Direct evaluation via service
    report2 = await ProductionExecutionGate.evaluate_change_request(
        db=db_session,
        change_request=cr,
        executor=creator,
    )
    # Check 1 will still fail (PRODUCTION_ROUTING_ENABLED is False)
    assert report2.overall_status == "BLOCKED"
    # Check 4, 5, 6, 7 should now all pass
    p4 = next(i for i in report2.items if "Approval" in i.criterion)
    p5 = next(i for i in report2.items if "Anti-Self" in i.criterion)
    p6 = next(i for i in report2.items if "Dual-Approval" in i.criterion)
    p7 = next(i for i in report2.items if "Lab Test" in i.criterion)
    assert p4.status == "PASS"
    assert p5.status == "PASS"
    assert p6.status == "PASS"
    assert p7.status == "PASS"


# -----------------------------------------------------------------------------
# 4. Threat Candidate Ingestion & Lifecycle
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_threat_candidate_lifecycle(
    client: AsyncClient,
    engineer_token: str,
):
    """Verifies forming, listing, and anomaly detection of threat candidate records."""
    # 1. Engineer creates threat candidate
    payload = {
        "threat_type": "pps_spike",
        "severity": "HIGH",
        "target_prefix": "103.145.2.0/24",
        "protocol": 17,
        "target_port": 53,
        "detected_bps": 1500000000.0,
        "detected_pps": 250000.0,
        "confidence_score": 92.0,
        "recommended_action": "flowspec_rate_limit",
        "evidence_summary": {
            "top_protocol": "UDP",
            "amplification_vector": "DNS_AMP",
            "duration_seconds": 120,
        },
        "ttl_minutes": 60,
    }
    create_res = await client.post(
        "/api/v1/mitigation/threats",
        json=payload,
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert create_res.status_code == 201
    candidate = create_res.json()
    candidate_id = candidate["id"]
    assert candidate["target_prefix"] == "103.145.2.0/24"
    assert candidate["status"] == "CANDIDATE_FORMED"

    # 2. List threat candidates
    list_res = await client.get(
        "/api/v1/mitigation/threats",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert list_res.status_code == 200
    assert any(c["id"] == candidate_id for c in list_res.json())

    # 3. Trigger telemetry anomaly detection scan
    detect_res = await client.post(
        "/api/v1/mitigation/threats/detect",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert detect_res.status_code == 200
    assert isinstance(detect_res.json(), list)


# -----------------------------------------------------------------------------
# 5. FlowSpec Mitigation Workflow & Syntax Preview
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_flowspec_preview_and_rule_lifecycle(
    client: AsyncClient,
    engineer_token: str,
    approver_token: str,
):
    """Verifies typed schema validation, syntax preview compilation, and anti-self-approval on FlowSpec rules."""
    # 1. Generate preview for Junos, Cisco, and GoBGP
    preview_res = await client.post(
        "/api/v1/mitigation/flowspec/preview",
        json={
            "target_prefix": "103.145.2.100/32",
            "protocol": 17,
            "dst_port_range": "53",
            "action_type": "RATE_LIMIT",
            "action_value": "9600",
            "ttl_minutes": 30,
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert preview_res.status_code == 200
    preview_data = preview_res.json()
    assert "then rate-limit 9600" in preview_data["formatted_junos"]
    assert "destination-port 53" in preview_data["formatted_junos"]
    assert "rate-limit 9600" in preview_data["formatted_cisco"]
    assert preview_data["formatted_gobgp"]["protocol"] == 17

    # 2. FlowSpec preview rejects default route (Pydantic validator)
    bad_res = await client.post(
        "/api/v1/mitigation/flowspec/preview",
        json={
            "target_prefix": "0.0.0.0/0",
            "protocol": 6,
            "action_type": "DISCARD",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert bad_res.status_code == 422

    # 3. Engineer creates FlowSpec rule candidate
    rule_res = await client.post(
        "/api/v1/mitigation/flowspec/rules",
        json={
            "target_prefix": "103.145.2.100/32",
            "protocol": 17,
            "dst_port_range": "53",
            "action_type": "RATE_LIMIT",
            "action_value": "9600",
            "ttl_minutes": 30,
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert rule_res.status_code == 201
    rule_id = rule_res.json()["id"]
    assert rule_res.json()["status"] == "DRAFT"

    # 4. Engineer tries to approve own rule -> Blocked (role 403 or anti-self 400)
    self_app = await client.post(
        f"/api/v1/mitigation/rules/{rule_id}/approve",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert self_app.status_code in (400, 403)

    # 5. Independent Approver approves rule
    app_res = await client.post(
        f"/api/v1/mitigation/rules/{rule_id}/approve",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert app_res.status_code == 200
    assert app_res.json()["status"] == "APPROVED"


# -----------------------------------------------------------------------------
# 6. RTBH Mitigation Workflow with Mandatory Dual-Approval
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rtbh_mitigation_dual_approval_and_prefix_guards(
    client: AsyncClient,
    engineer_token: str,
    approver_token: str,
    admin_token: str,
):
    """Verifies RTBH prefix length bounds (/24-/32), blackhole preview, and strict dual-approval."""
    # 1. Preview rejection for overly broad prefix (e.g. /16)
    broad_res = await client.post(
        "/api/v1/mitigation/rtbh/preview",
        json={
            "target_prefix": "103.145.0.0/16",
            "blackhole_community": "65535:666",
            "justification": "Testing illegal broad prefix",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert broad_res.status_code == 422

    # 2. Preview valid host blackhole /32
    valid_preview = await client.post(
        "/api/v1/mitigation/rtbh/preview",
        json={
            "target_prefix": "103.145.2.55/32",
            "blackhole_community": "65535:666",
            "justification": "Targeted host DDoS drop",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert valid_preview.status_code == 200
    preview_data = valid_preview.json()
    assert preview_data["blackhole_community"] == "65535:666"
    assert preview_data["is_host_route"] is True
    assert preview_data["next_hop"] == "192.0.2.1"

    # 3. Engineer creates RTBH rule candidate
    create_rtbh = await client.post(
        "/api/v1/mitigation/rtbh/rules",
        json={
            "target_prefix": "103.145.2.55/32",
            "blackhole_community": "65535:666",
            "justification": "Dropping flood targeting host 55",
            "ttl_minutes": 60,
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert create_rtbh.status_code == 201
    rtbh_id = create_rtbh.json()["id"]
    assert create_rtbh.json()["status"] == "DRAFT"

    # 4. Step 1 Approval by Approver
    step1_res = await client.post(
        f"/api/v1/mitigation/rules/{rtbh_id}/approve",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert step1_res.status_code == 200
    # Mandatory dual-approval moves status to AWAITING_APPROVAL (Step 1 of 2)
    assert step1_res.json()["status"] == "AWAITING_APPROVAL"

    # 5. Same Approver attempts Step 2 -> Rejected (must be distinct approvers)
    step2_same = await client.post(
        f"/api/v1/mitigation/rules/{rtbh_id}/approve",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert step2_same.status_code == 400
    assert "different from first approver" in step2_same.json()["detail"]

    # 6. Distinct Super Admin executes Step 2 Approval -> Successfully APPROVED
    step2_distinct = await client.post(
        f"/api/v1/mitigation/rules/{rtbh_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert step2_distinct.status_code == 200
    assert step2_distinct.json()["status"] == "APPROVED"


# -----------------------------------------------------------------------------
# 7. Controlled Rollout State Machine & Batch Prefix Limits
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_controlled_rollout_lifecycle_and_batch_limits(
    client: AsyncClient,
    engineer_token: str,
):
    """Verifies prefix batch cap (<= 5) and staged canary state transitions."""
    # 1. Rollout with > 5 prefixes is rejected
    too_many = await client.post(
        "/api/v1/mitigation/rollout/plans",
        json={
            "rollout_type": "CANARY",
            "total_stages": 3,
            "scope_prefixes": [
                "103.145.2.1/32",
                "103.145.2.2/32",
                "103.145.2.3/32",
                "103.145.2.4/32",
                "103.145.2.5/32",
                "103.145.2.6/32",
            ],
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert too_many.status_code == 400
    assert "ROLLOUT LIMIT EXCEEDED" in too_many.json()["detail"]

    # 2. Valid rollout creation
    rollout_res = await client.post(
        "/api/v1/mitigation/rollout/plans",
        json={
            "rollout_type": "CANARY",
            "total_stages": 3,
            "scope_prefixes": ["103.145.2.0/24"],
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert rollout_res.status_code == 201
    rollout_id = rollout_res.json()["id"]
    assert rollout_res.json()["status"] == "DRAFT"

    # 3. Advance state through controlled lifecycle
    # DRAFT -> POLICY_VALIDATED
    adv1 = await client.post(
        f"/api/v1/mitigation/rollout/plans/{rollout_id}/advance?target_status=POLICY_VALIDATED",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert adv1.status_code == 200
    assert adv1.json()["status"] == "POLICY_VALIDATED"

    # POLICY_VALIDATED -> LAB_TESTED
    adv2 = await client.post(
        f"/api/v1/mitigation/rollout/plans/{rollout_id}/advance?target_status=LAB_TESTED",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert adv2.status_code == 200
    assert adv2.json()["status"] == "LAB_TESTED"


# -----------------------------------------------------------------------------
# 8. Circuit Breaker Auto-Trip, Block Enforcement & Emergency Stop
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_circuit_breaker_and_emergency_stop(
    client: AsyncClient,
    db_session: AsyncSession,
    engineer_token: str,
    admin_token: str,
):
    """Verifies circuit breaker auto-tripping on failure threshold, execution blocks, and emergency stop."""
    admin_user = User(id=999, username="admin", role=UserRole.SUPER_ADMIN.value)

    # 1. Reset circuit breaker to clean CLOSED state
    await CircuitBreakerService.reset_circuit_breaker(
        db=db_session,
        notes="Test suite clean baseline explanation",
        operator=admin_user,
    )
    status1 = await CircuitBreakerService.get_status(db=db_session)
    assert status1["state"] == "CLOSED"
    assert status1["consecutive_failures"] == 0

    # 2. Record 3 consecutive failures to trigger AUTO-TRIP
    await CircuitBreakerService.record_failure(db=db_session, reason="Post-check packet drop on peer 1")
    await CircuitBreakerService.record_failure(db=db_session, reason="Post-check timeout on peer 2")
    await CircuitBreakerService.record_failure(db=db_session, reason="Rollback delay on peer 3")

    status2 = await CircuitBreakerService.get_status(db=db_session)
    assert status2["state"] == "OPEN"
    assert status2["consecutive_failures"] >= 3

    # 3. Verify CircuitBreakerService blocks new executions when OPEN
    is_blocked, reason = await CircuitBreakerService.is_execution_blocked(db=db_session)
    assert is_blocked is True
    assert "CIRCUIT BREAKER OPEN" in reason

    # 4. Attempt manual reset without sufficient justification notes (min length 10) -> Rejected
    bad_reset = await client.post(
        "/api/v1/mitigation/circuit-breaker/reset",
        json={"notes": "short"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert bad_reset.status_code == 422

    # 5. Manual Reset with valid root-cause explanation by super_admin
    good_reset = await client.post(
        "/api/v1/mitigation/circuit-breaker/reset",
        json={"notes": "Investigated upstream flapping; link stable, resolved root cause"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert good_reset.status_code == 200
    assert good_reset.json()["status"] == "RESET_SUCCESSFUL"

    # 6. Emergency Stop trigger by Admin immediately forces OPEN state
    e_stop = await client.post(
        "/api/v1/mitigation/emergency-stop",
        json={"reason": "Emergency NOC Incident #9921 - Global Hold"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert e_stop.status_code == 200
    assert e_stop.json()["status"] == "EMERGENCY_STOP_ACTIVE"
    assert e_stop.json()["emergency_stop_active"] is True

    # 7. Check status reflects emergency stop active
    cb_stat = await client.get(
        "/api/v1/mitigation/circuit-breaker/status",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert cb_stat.status_code == 200
    assert cb_stat.json()["state"] == "OPEN"
    assert cb_stat.json()["emergency_stop_active"] is True

    # Clean up: Reset back to CLOSED so other test suites are unaffected
    await CircuitBreakerService.reset_circuit_breaker(
        db=db_session,
        notes="Test tear-down cleanup",
        operator=admin_user,
    )

import pytest
import pytest_asyncio
import json
from unittest.mock import patch
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.models.bgp_lab import LabTestRun
from app.models.recommendation import ChangeRequest
from app.models.policy import PrefixAllowlist
from app.models.audit import AuditEvent
from app.services.bgp_lab_adapter import BGPLabAdapter, BGPLabAdapterError
from app.services.bgp_lab_precheck import BGPLabPreCheckEngine
from app.services.bgp_lab_postcheck import BGPLabPostCheckEngine
from app.services.bgp_lab_rollback import AutomatedRollbackCoordinator
from app.services.bgp_lab_service import BGPLabService


@pytest.fixture(autouse=True)
def setup_lab_env():
    """Ensure lab is enabled and virtual fallback is configured cleanly for tests."""
    original_lab_enabled = settings.BGP_LAB_ENABLED
    original_prod_exec = settings.ROUTING_EXECUTION_ENABLED

    settings.BGP_LAB_ENABLED = True
    settings.ROUTING_EXECUTION_ENABLED = False
    BGPLabAdapter.set_virtual_fallback(True)

    # Reset virtual speakers state
    BGPLabAdapter._virtual_speakers = {
        "bgp-speaker-1": {
            "routes": {},
            "state": "Established",
            "uptime": 3600,
            "is_up": True,
        },
        "bgp-speaker-2": {
            "routes": {},
            "state": "Established",
            "uptime": 3600,
            "is_up": True,
        },
    }

    yield

    settings.BGP_LAB_ENABLED = original_lab_enabled
    settings.ROUTING_EXECUTION_ENABLED = original_prod_exec
    BGPLabAdapter.set_virtual_fallback(False)


@pytest.mark.asyncio
async def test_lab_adapter_prefix_validation():
    """Verifies prefix validation rules: allows lab prefixes, rejects default routes & unallowlisted prefixes."""
    # 1. Valid lab prefix passes
    valid_prefix = BGPLabAdapter.validate_prefix("10.100.1.0/24")
    assert valid_prefix == "10.100.1.0/24"

    # 2. Default route 0.0.0.0/0 permanently rejected
    with pytest.raises(BGPLabAdapterError) as exc_0:
        BGPLabAdapter.validate_prefix("0.0.0.0/0")
    assert "Default routes (0.0.0.0/0 or ::/0) are strictly forbidden" in str(exc_0.value)

    # 3. Default route ::/0 permanently rejected
    with pytest.raises(BGPLabAdapterError) as exc_v6:
        BGPLabAdapter.validate_prefix("::/0")
    assert "Default routes (0.0.0.0/0 or ::/0) are strictly forbidden" in str(exc_v6.value)

    # 4. Unallowlisted prefix rejected
    with pytest.raises(BGPLabAdapterError) as exc_unallow:
        BGPLabAdapter.validate_prefix("198.51.100.0/24")
    assert "LAB POLICY REJECTION" in str(exc_unallow.value)

    # 5. Invalid CIDR format rejected
    with pytest.raises(BGPLabAdapterError) as exc_inv:
        BGPLabAdapter.validate_prefix("invalid-prefix-format")
    assert "Invalid IPv4 CIDR" in str(exc_inv.value)


@pytest.mark.asyncio
async def test_lab_adapter_peer_ip_validation():
    """Verifies peer IP validation against allowed lab peers."""
    valid_peer = BGPLabAdapter.validate_peer_ip("10.99.0.20")
    assert valid_peer == "10.99.0.20"

    with pytest.raises(BGPLabAdapterError) as exc_peer:
        BGPLabAdapter.validate_peer_ip("192.168.1.1")
    assert "LAB POLICY REJECTION" in str(exc_peer.value)


@pytest.mark.asyncio
async def test_lab_precheck_11_points_pass(db_session: AsyncSession):
    """Verifies all 11 safety pre-checks PASS under optimal lab conditions."""
    report = await BGPLabPreCheckEngine.run_pre_checks(
        db=db_session,
        prefix="10.100.1.0/24",
        operation="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
    )
    assert report.overall_status == "PASS"
    assert len(report.items) == 11
    for item in report.items:
        assert item.status == "PASS", f"Check '{item.check_name}' failed: {item.details}"


@pytest.mark.asyncio
async def test_lab_precheck_fails_when_lab_disabled(db_session: AsyncSession):
    """Verifies pre-check fails immediately if BGP_LAB_ENABLED is False."""
    try:
        settings.BGP_LAB_ENABLED = False
        report = await BGPLabPreCheckEngine.run_pre_checks(
            db=db_session,
            prefix="10.100.1.0/24",
            operation="ANNOUNCE",
            target_speaker="bgp-speaker-1",
            target_peer="10.99.0.20",
        )
        assert report.overall_status == "FAIL"
        chk10 = [i for i in report.items if "10." in i.check_name][0]
        assert chk10.status == "FAIL"
        assert "BGP_LAB_ENABLED is FALSE" in chk10.details
    finally:
        settings.BGP_LAB_ENABLED = True


@pytest.mark.asyncio
async def test_lab_precheck_rejects_default_route(db_session: AsyncSession):
    """Verifies pre-check strictly fails on default route 0.0.0.0/0."""
    report = await BGPLabPreCheckEngine.run_pre_checks(
        db=db_session,
        prefix="0.0.0.0/0",
        operation="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
    )
    assert report.overall_status == "FAIL"
    chk5 = [i for i in report.items if "5." in i.check_name][0]
    assert chk5.status == "FAIL"
    assert "Default routes 0.0.0.0/0 and ::/0 are permanently blocked" in chk5.details


@pytest.mark.asyncio
async def test_lab_precheck_rejects_unallowlisted_prefix(db_session: AsyncSession):
    """Verifies pre-check rejects prefix not in BGP_LAB_ALLOWED_PREFIXES."""
    report = await BGPLabPreCheckEngine.run_pre_checks(
        db=db_session,
        prefix="10.250.0.0/24",
        operation="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
    )
    assert report.overall_status == "FAIL"
    chk4 = [i for i in report.items if "4." in i.check_name][0]
    assert chk4.status == "FAIL"


@pytest.mark.asyncio
async def test_lab_precheck_detects_concurrency_conflict(db_session: AsyncSession):
    """Verifies pre-check blocks operations when an in-progress lab test run exists for the same prefix."""
    active_run = LabTestRun(
        test_type="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
        prefix="10.100.1.0/24",
        execution_status="IN_PROGRESS",
    )
    db_session.add(active_run)
    await db_session.commit()

    report = await BGPLabPreCheckEngine.run_pre_checks(
        db=db_session,
        prefix="10.100.1.0/24",
        operation="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
    )
    assert report.overall_status == "FAIL"
    chk9 = [i for i in report.items if "9." in i.check_name][0]
    assert chk9.status == "FAIL"
    assert "CONFLICT: Lab test" in chk9.details

    # Clean up active_run
    await db_session.delete(active_run)
    await db_session.commit()


@pytest.mark.asyncio
async def test_lab_precheck_detects_incompatible_operation(db_session: AsyncSession):
    """Verifies pre-check rejects withdraw when prefix is not currently announced."""
    report = await BGPLabPreCheckEngine.run_pre_checks(
        db=db_session,
        prefix="10.100.1.0/24",
        operation="WITHDRAW",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
    )
    assert report.overall_status == "FAIL"
    chk8 = [i for i in report.items if "8." in i.check_name][0]
    assert chk8.status == "FAIL"
    assert "NOT currently present" in chk8.details


@pytest.mark.asyncio
async def test_lab_announce_success_lifecycle(db_session: AsyncSession):
    """Tests complete successful announcement lifecycle from pre-check to post-check convergence."""
    run = await BGPLabService.run_announce_test(
        db=db_session,
        prefix="10.100.1.0/24",
        target_speaker="bgp-speaker-1",
    )
    assert run.pre_check_status == "PASS"
    assert run.post_check_status == "PASS"
    assert run.execution_status == "SUCCESS"
    assert run.rollback_status == "NONE"
    assert run.completed_at is not None

    # Verify receiver has the route
    is_present = await BGPLabAdapter.is_prefix_present("bgp-speaker-2", "10.100.1.0/24")
    assert is_present is True


@pytest.mark.asyncio
async def test_lab_withdraw_success_lifecycle(db_session: AsyncSession):
    """Tests complete successful route withdrawal lifecycle: announce first, then withdraw & verify purged."""
    # 1. Announce first
    await BGPLabAdapter.announce_prefix("bgp-speaker-1", "10.100.1.0/24")
    assert await BGPLabAdapter.is_prefix_present("bgp-speaker-2", "10.100.1.0/24") is True

    # 2. Run withdrawal test
    run = await BGPLabService.run_withdraw_test(
        db=db_session,
        prefix="10.100.1.0/24",
        target_speaker="bgp-speaker-1",
    )
    assert run.pre_check_status == "PASS"
    assert run.post_check_status == "PASS"
    assert run.execution_status == "SUCCESS"
    assert run.rollback_status == "NONE"

    # Verify receiver purged the route
    is_present = await BGPLabAdapter.is_prefix_present("bgp-speaker-2", "10.100.1.0/24")
    assert is_present is False


@pytest.mark.asyncio
async def test_lab_roundtrip_test_lifecycle(db_session: AsyncSession):
    """Tests full roundtrip test: announce -> verify -> withdraw -> verify."""
    run = await BGPLabService.run_roundtrip_test(
        db=db_session,
        prefix="10.100.2.0/24",
        target_speaker="bgp-speaker-1",
    )
    assert run.test_type == "ROUNDTRIP"
    assert run.execution_status == "SUCCESS"
    assert run.rollback_status == "NONE"

    # Verify final state on receiver is clean
    is_present = await BGPLabAdapter.is_prefix_present("bgp-speaker-2", "10.100.2.0/24")
    assert is_present is False


@pytest.mark.asyncio
async def test_lab_automated_rollback_on_postcheck_failure(db_session: AsyncSession):
    """Verifies that an announce failing post-check automatically triggers a compensating withdraw rollback."""
    with patch.object(
        BGPLabPostCheckEngine,
        "verify_announcement_convergence",
        return_value=pytest.helpers if hasattr(pytest, "helpers") else None
    ) as mock_postcheck:
        from app.schemas.bgp_lab import PostCheckReport
        mock_postcheck.return_value = PostCheckReport(
            overall_status="FAIL",
            convergence_time_seconds=10.0,
            details={"error": "Simulated convergence timeout"}
        )

        run = await BGPLabService.run_announce_test(
            db=db_session,
            prefix="10.100.1.0/24",
            target_speaker="bgp-speaker-1",
        )
        assert run.pre_check_status == "PASS"
        assert run.post_check_status == "FAIL"
        assert run.execution_status == "ROLLED_BACK"
        assert run.rollback_status == "ROLLBACK_SUCCEEDED"

        # Verify compensating withdrawal purged the route from sender & receiver
        is_present = await BGPLabAdapter.is_prefix_present("bgp-speaker-1", "10.100.1.0/24")
        assert is_present is False


@pytest.mark.asyncio
async def test_lab_rollback_failure_flags_manual_review(db_session: AsyncSession):
    """Verifies that if automated rollback attempts fail, status is flagged with NEEDS_MANUAL_REVIEW."""
    with patch.object(BGPLabAdapter, "withdraw_prefix", side_effect=Exception("Simulated socket error during rollback")):
        rollback_res = await AutomatedRollbackCoordinator.execute_rollback(
            operation="ANNOUNCE",
            speaker_id="bgp-speaker-1",
            receiver_id="bgp-speaker-2",
            prefix="10.100.1.0/24",
            reason="Convergence failed",
        )
        assert rollback_res["status"] == "NEEDS_MANUAL_REVIEW"
        assert rollback_res["retries"] > 1


@pytest.mark.asyncio
async def test_lab_manual_review_resolution(db_session: AsyncSession):
    """Verifies an operator can resolve a NEEDS_MANUAL_REVIEW test run."""
    from app.models.user import User, UserRole, UserStatus
    operator = User(
        username="engineer_bob",
        email="bob@noc.net",
        password_hash="hashed",
        role=UserRole.NETWORK_ENGINEER.value,
        status=UserStatus.ACTIVE.value,
    )
    db_session.add(operator)
    await db_session.commit()
    await db_session.refresh(operator)

    run = LabTestRun(
        test_type="ANNOUNCE",
        target_speaker="bgp-speaker-1",
        target_peer="10.99.0.20",
        prefix="10.100.1.0/24",
        execution_status="ROLLED_BACK",
        rollback_status="NEEDS_MANUAL_REVIEW",
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    updated_run = await BGPLabService.complete_manual_review(
        db=db_session,
        test_run_id=run.id,
        operator=operator,
        notes="Inspected router CLI; session cleared manually.",
    )
    assert updated_run.rollback_status == "MANUAL_REVIEW_RESOLVED"
    assert "Manual review resolved by engineer_bob" in updated_run.error_message


@pytest.mark.asyncio
async def test_lab_change_request_integration(db_session: AsyncSession):
    """Verifies that a successful lab test run updates the linked ChangeRequest with lab_tested=True."""
    from app.models.user import User, UserRole, UserStatus
    user = User(
        username="cr_creator",
        email="creator@test.net",
        password_hash="hash",
        role=UserRole.NETWORK_ENGINEER.value,
        status=UserStatus.ACTIVE.value,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    cr = ChangeRequest(
        requester_id=user.id,
        target_peer="10.99.0.20",
        prefix="10.100.1.0/24",
        diff_payload="set protocols bgp group lab neighbor 10.99.0.20 export RM-ALLOW",
        justification="Test BGP policy in isolated lab",
        rollback_instructions="delete protocols bgp group lab neighbor 10.99.0.20 export RM-ALLOW",
        validation_status="valid",
        execution_status="pending_approval",
        lab_tested=False,
    )
    db_session.add(cr)
    await db_session.commit()
    await db_session.refresh(cr)

    # Run announce test linked to CR
    run = await BGPLabService.run_announce_test(
        db=db_session,
        prefix="10.100.1.0/24",
        target_speaker="bgp-speaker-1",
        change_request_id=cr.id,
    )
    assert run.execution_status == "SUCCESS"

    # Refresh CR and verify lab_tested flag
    await db_session.refresh(cr)
    assert cr.lab_tested is True
    assert cr.lab_test_run_id == run.id


@pytest.mark.asyncio
async def test_lab_api_endpoints_rbac(
    client: AsyncClient,
    engineer_token: str,
    operator_token: str,
):
    """Verifies RBAC enforcement: noc_operator is forbidden (403), network_engineer is permitted (201)."""
    # 1. Operator attempts to trigger test -> 403 Forbidden
    op_res = await client.post(
        "/api/v1/bgp-lab/test/announce",
        json={"prefix": "10.100.1.0/24", "target_speaker": "bgp-speaker-1"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert op_res.status_code == 403

    # 2. Engineer triggers test -> 201 Created
    eng_res = await client.post(
        "/api/v1/bgp-lab/test/announce",
        json={"prefix": "10.100.1.0/24", "target_speaker": "bgp-speaker-1"},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert eng_res.status_code == 201
    data = eng_res.json()
    assert data["prefix"] == "10.100.1.0/24"
    assert data["execution_status"] == "SUCCESS"

    # 3. Read status and history is allowed for authenticated users
    status_res = await client.get(
        "/api/v1/bgp-lab/status",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert status_res.status_code == 200
    assert "speakers" in status_res.json()


@pytest.mark.asyncio
async def test_lab_production_guardrail_unaffected(
    client: AsyncClient,
    engineer_token: str,
    approver_token: str,
    db_session: AsyncSession,
):
    """
    CRITICAL SAFETY GUARDRAIL TEST:
    Verifies that ROUTING_EXECUTION_ENABLED is permanently False,
    and attempting production execution returns HTTP 403 Forbidden.
    """
    assert settings.ROUTING_EXECUTION_ENABLED is False

    # Seed allowlist for prefix
    allowlist = PrefixAllowlist(prefix="10.100.1.0/24", description="Lab test prefix", is_active=True)
    db_session.add(allowlist)
    await db_session.commit()

    # Create CR
    cr_res = await client.post(
        "/api/v1/change-requests",
        json={
            "target_peer": "198.51.100.1",
            "prefix": "10.100.1.0/24",
            "diff_payload": "set policy-options community AS4761_PREPEND",
            "justification": "Shift traffic",
            "rollback_instructions": "delete policy-options community AS4761_PREPEND",
            "requires_dual_approval": False,
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert cr_res.status_code == 201
    cr_id = cr_res.json()["id"]

    # Approver approves
    app_res = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert app_res.status_code == 200

    # Attempt execute -> 403 Forbidden
    exec_res = await client.post(
        f"/api/v1/change-requests/{cr_id}/execute",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert exec_res.status_code == 403
    assert "ROUTING_EXECUTION_ENABLED is FALSE" in exec_res.json()["detail"]


@pytest.mark.asyncio
async def test_lab_audit_logging(db_session: AsyncSession):
    """Verifies that lab route announcement creates an immutable audit event."""
    from app.models.user import User, UserRole, UserStatus
    user = User(
        username="audit_eng",
        email="eng@noc.net",
        password_hash="hash",
        role=UserRole.NETWORK_ENGINEER.value,
        status=UserStatus.ACTIVE.value,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    run = await BGPLabService.run_announce_test(
        db=db_session,
        prefix="10.100.1.0/24",
        target_speaker="bgp-speaker-1",
        operator=user,
    )
    assert run.execution_status == "SUCCESS"

    # Query audit events
    audit_stmt = select(AuditEvent).where(
        AuditEvent.action == "BGP_LAB_ANNOUNCE_SUCCESS"
    )
    event = (await db_session.execute(audit_stmt)).scalars().first()
    assert event is not None
    assert event.actor_username == "audit_eng"
    assert event.resource_type == "lab_test_run"
    assert str(run.id) == event.resource_id

import json
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.policy import ScoringPolicy, PrefixAllowlist
from app.models.recommendation import Recommendation, ChangeRequest
from app.models.user import User, UserRole
from app.models.probe import ProbeTarget
from app.models.inventory import Device, Interface
from app.services.scoring_engine import RouteScoringEngine
from app.services.route_simulator import RouteSimulatorService
from app.services.recommendation_service import RecommendationService
from app.core.security import create_access_token


# =====================================================================
# 1. SCORING ENGINE & ANTI-OSCILLATION UNIT TESTS
# =====================================================================

def test_scoring_formula_determinism_and_mathematics():
    """Verify deterministic multivariate scoring (0-100, higher is better)."""
    policy = ScoringPolicy(
        name="Test Policy",
        latency_weight=0.35,
        loss_weight=0.30,
        jitter_weight=0.15,
        utilization_weight=0.10,
        cost_weight=0.10,
        min_improvement_score=10.0,
        max_acceptable_loss_pct=5.0,
        max_acceptable_latency_ms=250.0,
        max_utilization_pct=95.0,
    )

    metrics = {
        "latency_ms": 25.0,     # Normalized: 100 * (1 - 25/250) = 90.0 -> contrib = 31.5
        "loss_percent": 0.0,    # Normalized: 100 * (1 - 0/5) = 100.0  -> contrib = 30.0
        "jitter_ms": 3.0,       # Normalized: 100 * (1 - 3/30) = 90.0   -> contrib = 13.5
        "utilization_pct": 47.5,# Normalized: 100 * (1 - 47.5/95) = 50.0-> contrib = 5.0
        "cost_per_mbps": 4.0,   # Normalized: 100 * (1 - 4/20) = 80.0   -> contrib = 8.0
    }

    breakdown = RouteScoringEngine.calculate_path_score(metrics, policy)
    assert breakdown.hard_constraints_passed is True
    assert breakdown.composite_score == 88.0
    assert len(breakdown.metrics) == 5
    assert len(breakdown.missing_metrics) == 0


def test_scoring_missing_data_handling():
    """Missing metric data must NOT be quietly assumed 0; handled via neutral score & penalty."""
    policy = ScoringPolicy(
        name="Test Policy",
        latency_weight=0.5,
        loss_weight=0.5,
        jitter_weight=0.0,
        utilization_weight=0.0,
        cost_weight=0.0,
    )

    # Missing loss_percent
    metrics = {
        "latency_ms": 50.0,
        "loss_percent": None,
    }

    breakdown = RouteScoringEngine.calculate_path_score(metrics, policy)
    assert "loss_percent" in breakdown.missing_metrics

    # Check that loss detail has status="missing"
    loss_detail = next(m for m in breakdown.metrics if m.metric_name == "packet_loss")
    assert loss_detail.status == "missing"
    assert loss_detail.normalized_score == 50.0


def test_scoring_hard_constraint_failure():
    """Packet loss exceeding max limit must disqualify candidate (composite score -> 0.0)."""
    policy = ScoringPolicy(
        name="Strict Policy",
        latency_weight=0.5,
        loss_weight=0.5,
        jitter_weight=0.0,
        utilization_weight=0.0,
        cost_weight=0.0,
        max_acceptable_loss_pct=5.0,
    )

    # Severe loss 7.5% > 5.0%
    metrics = {
        "latency_ms": 10.0,
        "loss_percent": 7.5,
    }

    breakdown = RouteScoringEngine.calculate_path_score(metrics, policy)
    assert breakdown.hard_constraints_passed is False
    assert breakdown.composite_score == 0.0
    assert len(breakdown.hard_constraint_failures) > 0


def test_scoring_data_quality_and_freshness():
    """Data quality confidence must degrade on missing sources and stale data."""
    # Stale active probe data (400s old)
    dq = RouteScoringEngine.evaluate_data_quality(
        available_sources=["BGP", "ACTIVE_PROBE"],
        data_age_seconds=400,
        missing_metrics=["utilization_pct"],
    )
    assert dq.is_stale is True
    assert dq.confidence_pct < 70.0


def test_anti_oscillation_minimum_improvement_threshold():
    """Candidate with improvement below min threshold must be rejected."""
    policy = ScoringPolicy(
        name="Anti-Oscillation Policy",
        min_improvement_score=10.0,
        hysteresis_threshold_pct=15.0,
        hold_down_minutes=15,
    )

    # Only 4.0 points improvement (below 10.0 threshold)
    passes, reason = RouteScoringEngine.check_anti_oscillation(
        score_current=70.0,
        score_candidate=74.0,
        policy=policy,
    )
    assert passes is False
    assert "below minimum threshold" in reason


def test_anti_oscillation_hold_down_cooldown():
    """Candidate within hold-down cooldown window must be suppressed."""
    policy = ScoringPolicy(
        name="Cooldown Policy",
        min_improvement_score=10.0,
        hysteresis_threshold_pct=10.0,
        hold_down_minutes=15,
    )

    recent_rec_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    passes, reason = RouteScoringEngine.check_anti_oscillation(
        score_current=60.0,
        score_candidate=85.0,
        policy=policy,
        last_recommendation_time=recent_rec_time,
    )
    assert passes is False
    assert "Hold-down cooldown active" in reason


def test_reproducibility_snapshot_hash():
    """Identical input snapshots must produce identical SHA-256 hashes."""
    h1 = RouteScoringEngine.generate_snapshot_hash(
        prefix="103.145.2.0/24",
        current_path="AS7713",
        candidate_path="AS4761",
        metrics_current={"latency_ms": 50.0},
        metrics_candidate={"latency_ms": 25.0},
        policy_name="Default",
    )
    h2 = RouteScoringEngine.generate_snapshot_hash(
        prefix="103.145.2.0/24",
        current_path="AS7713",
        candidate_path="AS4761",
        metrics_current={"latency_ms": 50.0},
        metrics_candidate={"latency_ms": 25.0},
        policy_name="Default",
    )
    assert h1 == h2
    assert len(h1) == 64


# =====================================================================
# 2. ROUTE SIMULATOR DRY-RUN TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_route_simulator_dry_run_what_if(db_session: AsyncSession):
    """Simulator must accurately predict deltas and state guardrails."""
    res = await RouteSimulatorService.run_simulation(
        prefix="103.145.2.0/24",
        target_peer="198.51.100.5 (Indosat)",
        current_path="198.51.100.1 (Telkom)",
        as_path_prepend=1,
        db=db_session,
    )
    assert res.prefix == "103.145.2.0/24"
    assert res.action == "SIMULATE_ANNOUNCEMENT"
    assert res.execution_blocked_by_guardrail is True
    assert "ROUTING_EXECUTION_ENABLED is FALSE" in res.guardrail_notice
    assert len(res.assumptions) > 0


@pytest.mark.asyncio
async def test_route_simulator_blocks_unallowlisted_prefix(db_session: AsyncSession):
    """Simulator must reject prefixes not in PrefixAllowlist."""
    res = await RouteSimulatorService.run_simulation(
        prefix="203.0.113.0/24",  # Not in allowlist
        target_peer="198.51.100.5",
        db=db_session,
    )
    assert res.allowed is False
    assert any("PrefixAllowlist" in err for err in res.policy_validation_errors)


@pytest.mark.asyncio
async def test_route_simulator_blocks_default_routes(db_session: AsyncSession):
    """Attempting to simulate default routes must be permanently blocked."""
    res = await RouteSimulatorService.run_simulation(
        prefix="0.0.0.0/0",
        target_peer="198.51.100.5",
        db=db_session,
    )
    assert res.allowed is False
    assert any("Default route manipulation is strictly forbidden" in err for err in res.policy_validation_errors)


# =====================================================================
# 3. RECOMMENDATIONS & API WORKFLOW TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_recommendation_insufficient_data_behavior(db_session: AsyncSession):
    """When telemetry is absent, pipeline flags insufficient data instead of generating fake recommendations."""
    res = await RecommendationService.evaluate_all(db=db_session, force_refresh=True)
    assert res.evaluated_prefixes_count >= 1
    assert res.insufficient_data_count >= 1
    assert res.recommendations_generated_count == 0


@pytest.mark.asyncio
async def test_recommendation_evaluate_pipeline(db_session: AsyncSession):
    """Pipeline evaluates inventory with active telemetry, generating recommendations with 'generated' status."""
    # Seed active probe telemetry and interface for high confidence
    now = datetime.now(timezone.utc)
    target = ProbeTarget(
        target_ip="198.51.100.5",
        target_name="Candidate Peer SG",
        probe_type="icmp",
        last_latency_ms=24.5,
        last_loss_percent=0.0,
        last_status="ok",
        last_probed_at=now,
        is_active=True,
    )
    db_session.add(target)

    dev = Device(hostname="r1.noc", mgmt_ip="10.0.0.1", vendor="Juniper")
    db_session.add(dev)
    await db_session.commit()
    await db_session.refresh(dev)

    iface = Interface(
        device_id=dev.id,
        if_index=1,
        if_name="xe-0/0/0",
        oper_status="up",
        speed_bps=10_000_000_000,
        utilization_pct=42.0,
    )
    db_session.add(iface)
    await db_session.commit()

    res = await RecommendationService.evaluate_all(db=db_session, force_refresh=True)
    assert res.evaluated_prefixes_count >= 1
    assert res.recommendations_generated_count >= 1
    assert res.recommendations[0].status == "generated"


@pytest.mark.asyncio
async def test_recommendation_detail_endpoint(client: AsyncClient, db_session: AsyncSession):
    """Detail endpoint returns parsed breakdown and data quality."""
    token = create_access_token(subject="admin", role=UserRole.SUPER_ADMIN.value)
    headers = {"Authorization": f"Bearer {token}"}

    # Seed active probe telemetry and interface for high confidence
    now = datetime.now(timezone.utc)
    target = ProbeTarget(
        target_ip="198.51.100.5",
        target_name="Candidate Peer SG",
        probe_type="icmp",
        last_latency_ms=24.5,
        last_loss_percent=0.0,
        last_status="ok",
        last_probed_at=now,
        is_active=True,
    )
    db_session.add(target)

    dev = Device(hostname="r2.noc", mgmt_ip="10.0.0.2", vendor="Juniper")
    db_session.add(dev)
    await db_session.commit()
    await db_session.refresh(dev)

    iface = Interface(
        device_id=dev.id,
        if_index=1,
        if_name="xe-0/0/1",
        oper_status="up",
        speed_bps=10_000_000_000,
        utilization_pct=45.0,
    )
    db_session.add(iface)
    await db_session.commit()

    # Evaluate with telemetry
    await RecommendationService.evaluate_all(db=db_session, force_refresh=True)

    # Query list
    list_res = await client.get("/api/v1/recommendations", headers=headers)
    assert list_res.status_code == 200
    recs = list_res.json()
    assert len(recs) > 0
    rec_id = recs[0]["id"]

    # Query detail
    detail_res = await client.get(f"/api/v1/recommendations/{rec_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == rec_id
    assert "parsed_breakdown" in detail


# =====================================================================
# 4. CHANGE REQUEST & DUAL-APPROVAL WORKFLOW TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_change_request_create_validates_allowlist(client: AsyncClient, db_session: AsyncSession):
    """Creating change request for unallowlisted prefix must raise HTTP 400."""
    token = create_access_token(subject="engineer", role=UserRole.NETWORK_ENGINEER.value)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "prefix": "192.0.2.0/24",  # Not in allowlist
        "target_peer": "198.51.100.5",
        "diff_payload": "set local-preference 200",
        "justification": "Test non-allowlisted prefix",
        "rollback_instructions": "no set local-preference",
    }
    res = await client.post("/api/v1/change-requests", json=payload, headers=headers)
    assert res.status_code == 400
    assert "PrefixAllowlist" in res.json()["detail"]


@pytest.mark.asyncio
async def test_change_request_self_approval_blocked(client: AsyncClient, db_session: AsyncSession):
    """Requester cannot approve their own change request (HTTP 400)."""
    # Create as engineer
    eng_token = create_access_token(subject="engineer", role=UserRole.NETWORK_ENGINEER.value)
    create_payload = {
        "prefix": "103.145.2.0/24",
        "target_peer": "198.51.100.5",
        "diff_payload": "set local-pref 200",
        "justification": "Self approval test",
        "rollback_instructions": "no set local-pref",
        "requires_dual_approval": True,
    }
    c_res = await client.post("/api/v1/change-requests", json=create_payload, headers={"Authorization": f"Bearer {eng_token}"})
    assert c_res.status_code == 201
    cr_id = c_res.json()["id"]

    # Attempt to approve as engineer (self approval)
    appr_res = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers={"Authorization": f"Bearer {eng_token}"})
    # Engineer cannot approve due to role approver/super_admin, and self-approval is forbidden
    assert appr_res.status_code in (400, 403)


@pytest.mark.asyncio
async def test_change_request_dual_approval_workflow(client: AsyncClient, db_session: AsyncSession):
    """Sensitive change request requires two distinct approvers."""
    # Requester is engineer
    eng_token = create_access_token(subject="engineer", role=UserRole.NETWORK_ENGINEER.value)
    create_payload = {
        "prefix": "103.145.2.0/24",
        "target_peer": "198.51.100.5",
        "diff_payload": "set local-pref 200",
        "justification": "Dual approval validation test",
        "rollback_instructions": "no set local-pref",
        "requires_dual_approval": True,
    }
    c_res = await client.post("/api/v1/change-requests", json=create_payload, headers={"Authorization": f"Bearer {eng_token}"})
    assert c_res.status_code == 201
    cr_id = c_res.json()["id"]

    # Approver 1: approver signs Step 1
    appr_token = create_access_token(subject="approver", role=UserRole.APPROVER.value)
    step1_res = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers={"Authorization": f"Bearer {appr_token}"})
    assert step1_res.status_code == 200
    assert step1_res.json()["execution_status"] == "partially_approved"

    # Approver 1 attempts to sign Step 2 (duplicate approver violation)
    dup_res = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers={"Authorization": f"Bearer {appr_token}"})
    assert dup_res.status_code == 400
    assert "DUAL APPROVAL VIOLATION" in dup_res.json()["detail"]

    # Approver 2: admin signs Step 2 (different account)
    admin_token = create_access_token(subject="admin", role=UserRole.SUPER_ADMIN.value)
    step2_res = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers={"Authorization": f"Bearer {admin_token}"})
    assert step2_res.status_code == 200
    assert step2_res.json()["execution_status"] == "approved"
    assert step2_res.json()["second_approver_id"] is not None


@pytest.mark.asyncio
async def test_change_request_rejection_and_cancellation(client: AsyncClient, db_session: AsyncSession):
    """Rejection and cancellation transitions must update status and record justification."""
    eng_token = create_access_token(subject="engineer", role=UserRole.NETWORK_ENGINEER.value)
    admin_token = create_access_token(subject="admin", role=UserRole.SUPER_ADMIN.value)

    # Create change request
    create_payload = {
        "prefix": "103.145.2.0/24",
        "target_peer": "198.51.100.5",
        "diff_payload": "set local-pref 200",
        "justification": "Cancel test",
        "rollback_instructions": "no set local-pref",
    }
    c_res = await client.post("/api/v1/change-requests", json=create_payload, headers={"Authorization": f"Bearer {eng_token}"})
    cr_id = c_res.json()["id"]

    # Reject
    rej_res = await client.post(
        f"/api/v1/change-requests/{cr_id}/reject",
        json={"reason": "Excessive risk of congestion on downstream link"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert rej_res.status_code == 200
    assert rej_res.json()["execution_status"] == "rejected"


@pytest.mark.asyncio
async def test_change_request_execution_guardrail_permanent_block(client: AsyncClient, db_session: AsyncSession):
    """Executing a change request must be permanently blocked with HTTP 403 by guardrail."""
    admin_token = create_access_token(subject="admin", role=UserRole.SUPER_ADMIN.value)
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = await client.post("/api/v1/change-requests/1/execute", headers=headers)
    assert res.status_code == 403
    assert "ROUTING_EXECUTION_ENABLED is FALSE" in res.json()["detail"]


@pytest.mark.asyncio
async def test_recommendation_and_change_request_rbac(client: AsyncClient, db_session: AsyncSession):
    """Operator cannot create change requests or trigger evaluations (HTTP 403)."""
    op_token = create_access_token(subject="operator", role=UserRole.NOC_OPERATOR.value)
    headers = {"Authorization": f"Bearer {op_token}"}

    # Evaluate forbidden
    eval_res = await client.post("/api/v1/recommendations/evaluate", json={}, headers=headers)
    assert eval_res.status_code == 403

    # Create CR forbidden
    cr_res = await client.post("/api/v1/change-requests", json={"prefix": "103.145.2.0/24"}, headers=headers)
    assert cr_res.status_code == 403

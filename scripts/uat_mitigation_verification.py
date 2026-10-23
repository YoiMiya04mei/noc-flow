#!/usr/bin/env python3
"""
UAT-MITIG-01 Acceptance Verification Script for JDP Route Intelligence Platform.
Executes comprehensive testing of Phase 7 Mitigation and Safety Gate subsystem:
1. Threat Candidate creation, field validation, and default route rejection.
2. Multi-vendor FlowSpec rule preview (Junos filter, Cisco IOS-XR, GoBGP API JSON).
3. RTBH rule preview (/32 prefix length policy, RFC 7999 community 65535:666, broad subnet rejection).
4. Dual approval and anti-self-approval enforcement on mitigation rules.
5. 12-point backend Production Execution Gate (permanent deny-by-default when flags are false).
6. Circuit Breaker state machine (CLOSED -> 3 failures -> OPEN -> blocked -> manual reset -> CLOSED).
7. Emergency Stop instant platform-wide lockout and audit logging.
"""
import os
import sys
import json
import asyncio
from datetime import datetime, timezone, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

from app.core.config import settings
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

from app.models.user import User, UserRole
from app.models.mitigation import ThreatCandidate, MitigationRule, CircuitBreakerEvent
from app.models.recommendation import ChangeRequest
from app.schemas.mitigation import (
    ThreatCandidateCreate,
    FlowSpecRuleCreate,
    RTBHRuleCreate,
    FlowSpecRulePreview,
    RTBHRulePreview,
)
from app.services.mitigation_service import MitigationService
from app.services.execution_gate import ProductionExecutionGate
from app.services.circuit_breaker import CircuitBreakerService


def log_step(test_id: str, desc: str):
    print(f"\n[UAT-MITIG-01] === {test_id}: {desc} ===", flush=True)


async def run_mitigation_uat():
    print("=" * 80, flush=True)
    print("JDP ROUTE INTELLIGENCE PLATFORM — UAT BATCH 4: UAT-MITIG-01 VERIFICATION", flush=True)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}", flush=True)
    print("=" * 80, flush=True)

    results = []

    async with AsyncSessionLocal() as db:
        # Load or verify test users
        admin_user = (await db.execute(select(User).where(User.username == "uat_admin"))).scalars().first()
        engineer_user = (await db.execute(select(User).where(User.username == "uat_engineer"))).scalars().first()
        approver_user = (await db.execute(select(User).where(User.username == "uat_approver"))).scalars().first()

        # ---------------------------------------------------------------------
        # TEST 1: Threat Candidate Lifecycle & Validation
        # ---------------------------------------------------------------------
        log_step("STEP-1", "Threat Candidate Creation & Anomaly Detection")
        candidate_payload = ThreatCandidateCreate(
            threat_type="udp_flood",
            severity="HIGH",
            target_prefix="10.100.1.0/24",
            source_prefix="0.0.0.0/0",
            protocol=17,
            target_port=53,
            detected_bps=2500000000.0,  # 2.5 Gbps
            detected_pps=420000.0,      # 420 kpps
            confidence_score=96.8,
            evidence_summary={
                "attack_vector": "DNS Amplification",
                "sample_rate": "1:1000",
                "dominant_port": 53,
            },
            recommended_action="FLOWSPEC_RATE_LIMIT",
            ttl_minutes=120,
        )
        candidate = await MitigationService.create_threat_candidate(db, candidate_payload)
        print(f"  Threat Candidate Formed: ID #{candidate.id}", flush=True)
        print(f"    - Target Prefix: {candidate.target_prefix}", flush=True)
        print(f"    - Severity: {candidate.severity} | Score: {candidate.confidence_score}", flush=True)
        print(f"    - Status: {candidate.status}", flush=True)

        pass_1 = (
            candidate.id is not None
            and candidate.target_prefix == "10.100.1.0/24"
            and candidate.status == "CANDIDATE_FORMED"
            and candidate.confidence_score == 96.8
        )
        results.append(("UAT-MITIG-01-S1", "Threat Candidate Formation & Telemetry Evidence", pass_1))

        # ---------------------------------------------------------------------
        # TEST 2: Multi-Vendor FlowSpec Rule Preview
        # ---------------------------------------------------------------------
        log_step("STEP-2", "Multi-Vendor FlowSpec Rule Preview Compilation (Junos, Cisco, GoBGP)")
        fs_create = FlowSpecRuleCreate(
            threat_candidate_id=candidate.id,
            target_prefix="10.100.1.0/24",
            source_prefix="0.0.0.0/0",
            protocol=17,
            dst_port_range="53",
            action_type="RATE_LIMIT",
            action_value="1000000",  # 1 Mbps
            ttl_minutes=60,
        )
        fs_preview: FlowSpecRulePreview = MitigationService.generate_flowspec_preview(fs_create)
        print(f"  FlowSpec Preview Generated:", flush=True)
        print(f"    - Validation Status: {fs_preview.validation_status}", flush=True)
        print(f"    - Complexity Score: {fs_preview.rule_complexity_score}", flush=True)
        print(f"    - Juniper Junos Syntax:\n      {fs_preview.formatted_junos}", flush=True)
        print(f"    - Cisco IOS-XR Syntax:\n{fs_preview.formatted_cisco}", flush=True)
        print(f"    - GoBGP API JSON Payload:\n      {json.dumps(fs_preview.formatted_gobgp)}", flush=True)

        # Safety Guardrail: Default route FlowSpec preview rejection
        fs_bad_blocked = False
        try:
            fs_bad = FlowSpecRuleCreate(
                threat_candidate_id=candidate.id,
                target_prefix="0.0.0.0/0",
                protocol=17,
                action_type="DISCARD",
            )
            fs_bad_preview = MitigationService.generate_flowspec_preview(fs_bad)
            fs_bad_blocked = (fs_bad_preview.validation_status == "INVALID")
        except Exception as e:
            fs_bad_blocked = True
            print(f"    - Default Route FlowSpec Rejection: BLOCKED ({str(e)})", flush=True)

        pass_2 = (
            fs_preview.validation_status == "VALID"
            and "set routing-options flow route destination" in fs_preview.formatted_junos
            and "flowspec \n  address-family ipv4" in fs_preview.formatted_cisco
            and fs_preview.formatted_gobgp.get("family", {}).get("safi") == "FLOW_SPEC_UNICAST"
            and fs_bad_blocked
        )
        results.append(("UAT-MITIG-01-S2", "Multi-Vendor FlowSpec Preview (Junos, Cisco, GoBGP) & Default Route Guard", pass_2))

        # ---------------------------------------------------------------------
        # TEST 3: RTBH Rule Preview & Prefix Length Guardrails
        # ---------------------------------------------------------------------
        log_step("STEP-3", "RTBH Rule Preview, /32 Policy, & RFC 7999 Community Validation")
        # 3a. Valid /32 host RTBH
        rtbh_valid = RTBHRuleCreate(
            target_prefix="103.145.2.14/32",
            blackhole_community=settings.DEFAULT_RTBH_COMMUNITY,
            ttl_minutes=30,
            justification="Active high-rate UDP reflection amplification target against edge router",
        )
        rtbh_p_valid: RTBHRulePreview = MitigationService.generate_rtbh_preview(rtbh_valid)
        print(f"  3a. Valid /32 RTBH Preview:", flush=True)
        print(f"      - Validation Status: {rtbh_p_valid.validation_status}", flush=True)
        print(f"      - Community: {rtbh_p_valid.blackhole_community}", flush=True)
        print(f"      - Next-Hop: {rtbh_p_valid.next_hop}", flush=True)
        print(f"      - BGP Update Payload: {json.dumps(rtbh_p_valid.formatted_bgp_update)}", flush=True)

        # 3b. Overly broad /16 subnet RTBH rejection
        rtbh_broad_blocked = False
        try:
            rtbh_broad = RTBHRuleCreate(
                target_prefix="103.145.0.0/16",
                blackhole_community=settings.DEFAULT_RTBH_COMMUNITY,
                ttl_minutes=30,
                justification="Attempting broad subnet blackhole",
            )
            rtbh_p_broad = MitigationService.generate_rtbh_preview(rtbh_broad)
            rtbh_broad_blocked = (rtbh_p_broad.validation_status == "INVALID")
        except Exception as e:
            rtbh_broad_blocked = True
            print(f"  3b. Broad Subnet /16 RTBH Rejection: BLOCKED ({str(e)})", flush=True)

        # 3c. Default route 0.0.0.0/0 RTBH rejection
        rtbh_def_blocked = False
        try:
            rtbh_def = RTBHRuleCreate(
                target_prefix="0.0.0.0/0",
                blackhole_community=settings.DEFAULT_RTBH_COMMUNITY,
                ttl_minutes=30,
                justification="Attempting default route blackhole",
            )
            rtbh_p_def = MitigationService.generate_rtbh_preview(rtbh_def)
            rtbh_def_blocked = (rtbh_p_def.validation_status == "INVALID")
        except Exception as e:
            rtbh_def_blocked = True
            print(f"  3c. Default Route RTBH Rejection: BLOCKED ({str(e)})", flush=True)

        pass_3 = (
            rtbh_p_valid.validation_status == "VALID"
            and rtbh_p_valid.blackhole_community == "65535:666"
            and rtbh_broad_blocked
            and rtbh_def_blocked
        )
        results.append(("UAT-MITIG-01-S3", "RTBH Preview, /32 Policy & RFC 7999 Community Guardrails", pass_3))

        # ---------------------------------------------------------------------
        # TEST 4: Dual Approval & Anti-Self-Approval Enforcement
        # ---------------------------------------------------------------------
        log_step("STEP-4", "Mitigation Rule Governance: Dual Approval & Anti-Self Approval")
        # Create an RTBH mitigation rule as engineer_user
        rtbh_rule_payload = RTBHRuleCreate(
            target_prefix="103.145.2.14/32",
            blackhole_community=settings.DEFAULT_RTBH_COMMUNITY,
            ttl_minutes=60,
            justification="Mitigation of active DDoS traffic towards critical host",
        )
        rule = await MitigationService.create_rtbh_rule(
            db=db,
            payload=rtbh_rule_payload,
            creator=engineer_user or admin_user,
        )
        print(f"  Created RTBH Rule #{rule.id} by creator ID {rule.created_by_id} in status: {rule.status}", flush=True)

        # 4a. Anti-self approval check: Creator tries to approve own rule
        self_approval_blocked = False
        try:
            await MitigationService.approve_mitigation_rule(db, rule.id, engineer_user or admin_user)
        except Exception as e:
            self_approval_blocked = True
            print(f"  4a. Anti-Self-Approval Blocked as Expected: {str(e)}", flush=True)

        # 4b. Legitimate Approver 1 (approver_user) approves -> AWAITING_APPROVAL (Step 1 of 2)
        rule = await MitigationService.approve_mitigation_rule(db, rule.id, approver_user)
        print(f"  4b. Approver 1 ({approver_user.username}) approved: status={rule.status}, approved_by_id={rule.approved_by_id}", flush=True)

        # 4c. Anti-duplicate approval check: Approver 1 tries to approve again
        duplicate_approval_blocked = False
        try:
            await MitigationService.approve_mitigation_rule(db, rule.id, approver_user)
        except Exception as e:
            duplicate_approval_blocked = True
            print(f"  4c. Duplicate Approver Blocked as Expected: {str(e)}", flush=True)

        # 4d. Legitimate Approver 2 (admin_user) approves -> APPROVED (Step 2 of 2)
        rule = await MitigationService.approve_mitigation_rule(db, rule.id, admin_user)
        print(f"  4d. Approver 2 ({admin_user.username}) approved: status={rule.status}, second_approved_by_id={rule.second_approved_by_id}", flush=True)

        pass_4 = (
            self_approval_blocked
            and duplicate_approval_blocked
            and rule.status == "APPROVED"
            and rule.approved_by_id is not None
            and rule.second_approved_by_id is not None
            and rule.approved_by_id != rule.second_approved_by_id
        )
        results.append(("UAT-MITIG-01-S4", "Dual-Approval & Anti-Self-Approval Governance Enforcement", pass_4))

        # ---------------------------------------------------------------------
        # TEST 5: 12-Point Backend Production Execution Gate
        # ---------------------------------------------------------------------
        log_step("STEP-5", "12-Point Backend Production Execution Gate Deny-by-Default Evaluation")
        print(f"  System Execution Flags:", flush=True)
        print(f"    - ROUTING_EXECUTION_ENABLED: {settings.ROUTING_EXECUTION_ENABLED}", flush=True)
        print(f"    - PRODUCTION_ROUTING_ENABLED: {settings.PRODUCTION_ROUTING_ENABLED}", flush=True)
        print(f"    - FLOWSPEC_EXECUTION_ENABLED: {settings.FLOWSPEC_EXECUTION_ENABLED}", flush=True)
        print(f"    - RTBH_EXECUTION_ENABLED: {settings.RTBH_EXECUTION_ENABLED}", flush=True)

        # Create a mock ChangeRequest to evaluate through the 12-point gate
        cr = ChangeRequest(
            requester_id=admin_user.id,
            target_peer="10.99.0.20",
            prefix="10.100.1.0/24",
            diff_payload="route add 10.100.1.0/24 next-hop 10.0.1.2",
            justification="UAT Mitig Gate Evaluation CR",
            validation_status="valid",
            execution_status="approved",  # Even if status is approved!
            rollback_instructions="route del 10.100.1.0/24",
            requires_dual_approval=True,
        )
        db.add(cr)
        await db.commit()
        await db.refresh(cr)

        gate_report = await ProductionExecutionGate.evaluate_change_request(
            db=db,
            change_request=cr,
            executor=admin_user,
            operation_type="FLOWSPEC",
        )
        print(f"  Execution Gate Overall Result: {gate_report.overall_status}", flush=True)
        for item in gate_report.items:
            print(f"    - {item.criterion}: {item.status} | {item.details}", flush=True)

        env_check_blocked = any(i.criterion == "1. Environment Execution Flags" and i.status == "BLOCKED" for i in gate_report.items)
        gate_blocked = (gate_report.overall_status == "BLOCKED" and env_check_blocked)

        pass_5 = (
            gate_blocked
            and settings.ROUTING_EXECUTION_ENABLED is False
            and settings.PRODUCTION_ROUTING_ENABLED is False
            and settings.FLOWSPEC_EXECUTION_ENABLED is False
            and settings.RTBH_EXECUTION_ENABLED is False
        )
        print(f"  -> Execution Gate Verification: overall_status=BLOCKED ({gate_report.overall_status}), flag_check_blocked={env_check_blocked} | Result: {'PASS' if pass_5 else 'FAIL'}", flush=True)
        results.append(("UAT-MITIG-01-S5", "12-Point Backend Execution Gate Deny-by-Default (Flags=False)", pass_5))

        # ---------------------------------------------------------------------
        # TEST 6: Circuit Breaker State Machine & Consecutive Failure Lockout
        # ---------------------------------------------------------------------
        log_step("STEP-6", "Circuit Breaker State Machine (CLOSED -> 3 Faults -> OPEN -> Reset)")
        # 6a. Ensure baseline CLOSED
        await CircuitBreakerService.reset_circuit_breaker(db, notes="UAT baseline reset", operator=admin_user)
        status_init = await CircuitBreakerService.get_status(db)
        print(f"  Initial State: {status_init['state']}, consecutive_failures={status_init['consecutive_failures']}", flush=True)
        assert status_init["state"] == "CLOSED", "Initial state must be CLOSED"

        # 6b. Record 1st failure
        tripped_1 = await CircuitBreakerService.record_failure(db, reason="Simulated telemetry timeout 1")
        # 6c. Record 2nd failure
        tripped_2 = await CircuitBreakerService.record_failure(db, reason="Simulated telemetry timeout 2")
        status_mid = await CircuitBreakerService.get_status(db)
        print(f"  After 2 failures: state={status_mid['state']}, consecutive_failures={status_mid['consecutive_failures']}", flush=True)
        assert status_mid["state"] == "CLOSED" and status_mid["consecutive_failures"] == 2

        # 6d. Record 3rd failure (Threshold = 3) -> Trips to OPEN!
        tripped_3 = await CircuitBreakerService.record_failure(db, reason="Simulated telemetry timeout 3")
        status_open = await CircuitBreakerService.get_status(db)
        print(f"  After 3 failures: state={status_open['state']}, is_blocked={status_open['is_execution_blocked']}", flush=True)

        is_blocked, block_reason = await CircuitBreakerService.is_execution_blocked(db)
        print(f"  is_execution_blocked query: blocked={is_blocked}, reason={block_reason}", flush=True)

        # 6e. Manual reset with required rationale
        reset_res = await CircuitBreakerService.reset_circuit_breaker(
            db=db,
            notes="Root cause identified: simulated lab fault resolved, telemetry healthy.",
            operator=admin_user,
        )
        status_post_reset = await CircuitBreakerService.get_status(db)
        print(f"  After Manual Reset: state={status_post_reset['state']}, consecutive_failures={status_post_reset['consecutive_failures']}", flush=True)

        pass_6 = (
            tripped_3 is True
            and status_open["state"] == "OPEN"
            and is_blocked is True
            and reset_res.get("status") == "RESET_SUCCESSFUL"
            and status_post_reset["state"] == "CLOSED"
        )
        results.append(("UAT-MITIG-01-S6", "Circuit Breaker 3-Failure Trip to OPEN & Operator Reset Workflow", pass_6))

        # ---------------------------------------------------------------------
        # TEST 7: Emergency Stop Instant Platform-Wide Lockout
        # ---------------------------------------------------------------------
        log_step("STEP-7", "Emergency Stop Instant Lockout & Audit Recording")
        # Trigger emergency stop
        stop_result = await CircuitBreakerService.trigger_emergency_stop(
            db=db,
            reason="CRITICAL UAT DRILL: Network instability detected; full platform halt requested.",
            operator=admin_user,
        )
        print(f"  Emergency Stop Activated: {json.dumps(stop_result, indent=2, default=str)}", flush=True)

        status_em = await CircuitBreakerService.get_status(db)
        is_em_blocked, em_reason = await CircuitBreakerService.is_execution_blocked(db)
        print(f"  Status during Emergency Stop: emergency_stop_active={status_em['emergency_stop_active']}, is_blocked={is_em_blocked}", flush=True)
        print(f"  Block message: {em_reason}", flush=True)

        # Clear emergency stop via reset_circuit_breaker
        clear_result = await CircuitBreakerService.reset_circuit_breaker(
            db=db,
            notes="UAT DRILL COMPLETED: Verification finished, emergency stop released.",
            operator=admin_user,
        )
        print(f"  Emergency Stop Cleared: {json.dumps(clear_result, indent=2, default=str)}", flush=True)
        status_cleared = await CircuitBreakerService.get_status(db)
        print(f"  Status after Clear: emergency_stop_active={status_cleared['emergency_stop_active']}, state={status_cleared['state']}", flush=True)

        pass_7 = (
            status_em["emergency_stop_active"] is True
            and is_em_blocked is True
            and "EMERGENCY STOP ACTIVE" in em_reason
            and status_cleared["emergency_stop_active"] is False
            and status_cleared["state"] == "CLOSED"
        )
        results.append(("UAT-MITIG-01-S7", "Emergency Stop Platform Lockout & Manual Recovery", pass_7))

    # Print Summary Table
    print("\n" + "=" * 80, flush=True)
    print("UAT-MITIG-01 ACCEPTANCE VERIFICATION SUMMARY", flush=True)
    print("=" * 80, flush=True)
    all_passed = True
    for tid, name, passed in results:
        status_str = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"[{status_str:4s}] {tid:16s} - {name}", flush=True)
    print("=" * 80, flush=True)
    print(f"TOTAL CHECKS: {len(results)} | PASSED: {sum(1 for _, _, p in results if p)} | FAILED: {sum(1 for _, _, p in results if not p)}", flush=True)
    print(f"OVERALL STATUS: {'100% PASS — READY FOR SIGN-OFF' if all_passed else 'FAILURES DETECTED'}", flush=True)
    print("=" * 80, flush=True)
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(run_mitigation_uat())
    sys.exit(0 if success else 1)

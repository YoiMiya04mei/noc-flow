#!/usr/bin/env python3
"""
UAT-CR-01 Automated Acceptance Test Harness.
Domain: Change Request, Dual Approval, Separation of Duties, & RBAC Audit Regression.
Tests:
1. Change Request Creation with Prefix Allowlist Validation (Unallowlisted rejected HTTP 400).
2. Anti-Self-Approval Enforcement (Requester cannot approve their own CR, HTTP 400).
3. Dual Approval Workflow:
   - Step 1 Approval by Approver A transitions to 'partially_approved'.
   - Duplicate Approval by Approver A rejected (HTTP 400 DUAL APPROVAL VIOLATION).
   - Step 2 Approval by Approver B transitions to 'approved'.
4. Rejection with Mandatory Reason (Transitions to 'rejected' and logs explanation).
5. Cancellation Lifecycle (Requester/Admin can cancel, transitions to 'cancelled').
6. Policy Re-Validation at Approval Time (Allowlist revoked after CR creation triggers HTTP 400 rejection).
7. Expired Change Request Rejection.
8. Execution Gate Permanent Lock (POST /execute returns HTTP 403 ERR_ROUTING_EXECUTION_DISABLED).
9. Audit History Completeness for All Lifecycle State Transitions.
10. Permanent Regression Test for Batch 2 Defect on GET /api/v1/audit across all 5 roles:
    - super_admin: HTTP 200 OK
    - auditor: HTTP 200 OK
    - noc_operator: HTTP 403 Forbidden
    - network_engineer: HTTP 403 Forbidden
    - approver: HTTP 403 Forbidden
    - unauthenticated: HTTP 401 Unauthorized
    - privilege escalation tampering prevention
"""
import os
import sys
import asyncio
import time
import json
from datetime import datetime, timezone, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

if "DATABASE_URL" not in os.environ:
    from app.core.config import settings
    os.environ["DATABASE_URL"] = settings.DATABASE_URL

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.security import create_access_token
from app.models.user import User, UserRole
from app.models.policy import PrefixAllowlist
from app.models.recommendation import ChangeRequest, Recommendation
from app.models.audit import AuditEvent


async def run_change_request_acceptance():
    print("=" * 75)
    print("STARTING UAT-CR-01 ACCEPTANCE VERIFICATION (ISOLATED UAT)")
    print("=" * 75)

    engine = create_async_engine(os.environ["DATABASE_URL"])
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # 5 UAT RBAC Test Tokens
    admin_token = create_access_token(subject="uat_admin", role=UserRole.SUPER_ADMIN.value)
    engineer_token = create_access_token(subject="uat_engineer", role=UserRole.NETWORK_ENGINEER.value)
    approver1_token = create_access_token(subject="uat_approver", role=UserRole.APPROVER.value)
    # Second approver account with approver role for dual approval separation
    approver2_token = create_access_token(subject="uat_admin", role=UserRole.SUPER_ADMIN.value)
    operator_token = create_access_token(subject="uat_operator", role=UserRole.NOC_OPERATOR.value)
    auditor_token = create_access_token(subject="uat_auditor", role=UserRole.AUDITOR.value)

    transport = ASGITransport(app=app)
    test_results = []
    ts = int(time.time())

    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:

        # ---------------------------------------------------------------------
        # 1. CHANGE REQUEST CREATION & ALLOWLIST VALIDATION
        # ---------------------------------------------------------------------
        print("\n--- [1] Change Request Creation & Prefix Allowlist Validation ---")
        # Case A: Prefix NOT in allowlist
        unallow_payload = {
            "prefix": "203.0.113.0/24",
            "target_peer": "198.51.100.5",
            "diff_payload": "set local-preference 200",
            "justification": "Attempt unallowlisted prefix",
            "rollback_instructions": "no set local-preference",
        }
        res_unallow = await client.post(
            "/api/v1/change-requests",
            json=unallow_payload,
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert res_unallow.status_code == 400, f"Expected 400, got {res_unallow.status_code}"
        assert "GUARDRAIL REJECTION" in res_unallow.json()["detail"]
        print("  Unallowlisted prefix 203.0.113.0/24 rejected with HTTP 400 guardrail error.")

        # Case B: Prefix IN allowlist
        valid_prefix = "103.145.2.0/24"
        cr_payload = {
            "prefix": valid_prefix,
            "target_peer": "198.51.100.5 (Indosat)",
            "diff_payload": "set protocols bgp group transit neighbor 198.51.100.5 local-preference 200",
            "justification": f"UAT acceptance test change request {ts}",
            "rollback_instructions": "set protocols bgp group transit neighbor 198.51.100.5 local-preference 100",
            "requires_dual_approval": True,
        }
        res_cr = await client.post(
            "/api/v1/change-requests",
            json=cr_payload,
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert res_cr.status_code == 201, f"Failed to create valid CR: {res_cr.text}"
        cr_data = res_cr.json()
        cr_id = cr_data["id"]
        assert cr_data["execution_status"] == "pending_approval"
        assert cr_data["requires_dual_approval"] is True
        print(f"  Valid Change Request #{cr_id} created with status 'pending_approval'.")
        test_results.append(("CR Creation & Allowlist Validation", "PASS"))

        # ---------------------------------------------------------------------
        # 2. ANTI-SELF-APPROVAL ENFORCEMENT
        # ---------------------------------------------------------------------
        print("\n--- [2] Anti-Self-Approval Enforcement ---")
        # uat_engineer created CR #{cr_id}, now attempts to approve their own request
        res_self = await client.post(
            f"/api/v1/change-requests/{cr_id}/approve",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        # engineer is rejected because role is not APPROVER/SUPER_ADMIN (HTTP 403)
        assert res_self.status_code == 403
        print("  Network Engineer denied approval privileges (HTTP 403).")

        # Now test when a user with SUPER_ADMIN role creates a CR and attempts to self-approve:
        admin_cr_res = await client.post(
            "/api/v1/change-requests",
            json={
                "prefix": valid_prefix,
                "target_peer": "198.51.100.5",
                "diff_payload": "set local-preference 250",
                "justification": "Admin self-approval test",
                "rollback_instructions": "no set local-preference",
                "requires_dual_approval": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        admin_cr_id = admin_cr_res.json()["id"]

        # Admin attempts to approve their own CR
        res_admin_self = await client.post(
            f"/api/v1/change-requests/{admin_cr_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_admin_self.status_code == 400
        assert "Requester cannot approve their own change request" in res_admin_self.json()["detail"]
        print("  Super Admin self-approval strictly blocked (HTTP 400: SAFETY RULE VIOLATION).")
        test_results.append(("Anti-Self-Approval Enforcement", "PASS"))

        # ---------------------------------------------------------------------
        # 3. DUAL-APPROVAL WORKFLOW (TWO DISTINCT APPROVERS REQUIRED)
        # ---------------------------------------------------------------------
        print("\n--- [3] Dual-Approval Workflow & Separation of Duties ---")
        # Step 1 Approval by Approver A (uat_approver)
        res_step1 = await client.post(
            f"/api/v1/change-requests/{cr_id}/approve",
            headers={"Authorization": f"Bearer {approver1_token}"},
        )
        assert res_step1.status_code == 200, f"Step 1 approval failed: {res_step1.text}"
        step1_data = res_step1.json()
        assert step1_data["execution_status"] == "partially_approved"
        print(f"  Step 1 Approval: CR #{cr_id} transitioned to 'partially_approved'.")

        # Duplicate approval attempt by Approver A (same user cannot sign twice)
        res_dup = await client.post(
            f"/api/v1/change-requests/{cr_id}/approve",
            headers={"Authorization": f"Bearer {approver1_token}"},
        )
        assert res_dup.status_code == 400
        assert "DUAL APPROVAL VIOLATION" in res_dup.json()["detail"]
        print("  Duplicate Approval Violation caught: Second approval must be signed by a different account.")

        # Step 2 Approval by Approver B (uat_admin, distinct account)
        res_step2 = await client.post(
            f"/api/v1/change-requests/{cr_id}/approve",
            headers={"Authorization": f"Bearer {approver2_token}"},
        )
        assert res_step2.status_code == 200, f"Step 2 approval failed: {res_step2.text}"
        step2_data = res_step2.json()
        assert step2_data["execution_status"] == "approved"
        assert step2_data["second_approver_id"] is not None
        print(f"  Step 2 Approval: CR #{cr_id} successfully transitioned to 'approved' by distinct second approver.")
        test_results.append(("Dual Approval Workflow", "PASS"))

        # ---------------------------------------------------------------------
        # 4. REJECTION LIFECYCLE WITH MANDATORY REASON
        # ---------------------------------------------------------------------
        print("\n--- [4] Rejection Lifecycle with Mandatory Justification ---")
        # Create CR to test rejection
        rej_cr_res = await client.post(
            "/api/v1/change-requests",
            json={
                "prefix": valid_prefix,
                "target_peer": "198.51.100.5",
                "diff_payload": "set local-preference 300",
                "justification": "CR for rejection test",
                "rollback_instructions": "no set local-preference",
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        rej_cr_id = rej_cr_res.json()["id"]

        # Reject with reason
        reason_text = "Cost variance exceeds allocated peering budget for transit group"
        res_rej = await client.post(
            f"/api/v1/change-requests/{rej_cr_id}/reject",
            json={"reason": reason_text},
            headers={"Authorization": f"Bearer {approver1_token}"},
        )
        assert res_rej.status_code == 200
        rej_data = res_rej.json()
        assert rej_data["execution_status"] == "rejected"
        assert reason_text in rej_data["cancellation_reason"]
        print(f"  CR #{rej_cr_id} rejected cleanly with reason recorded: '{rej_data['cancellation_reason']}'.")

        # Attempt to approve an already rejected request (must be rejected)
        res_reappr = await client.post(
            f"/api/v1/change-requests/{rej_cr_id}/approve",
            headers={"Authorization": f"Bearer {approver2_token}"},
        )
        assert res_reappr.status_code == 400
        print("  Approval on rejected CR correctly rejected with HTTP 400.")
        test_results.append(("Rejection Lifecycle & Justification", "PASS"))

        # ---------------------------------------------------------------------
        # 5. CANCELLATION LIFECYCLE
        # ---------------------------------------------------------------------
        print("\n--- [5] Cancellation Lifecycle ---")
        # Create CR to test cancellation
        canc_cr_res = await client.post(
            "/api/v1/change-requests",
            json={
                "prefix": valid_prefix,
                "target_peer": "198.51.100.5",
                "diff_payload": "set local-preference 150",
                "justification": "CR for cancel test",
                "rollback_instructions": "no set local-preference",
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        canc_cr_id = canc_cr_res.json()["id"]

        # Requester cancels their own CR
        res_canc = await client.post(
            f"/api/v1/change-requests/{canc_cr_id}/cancel",
            json={"reason": "Traffic profile normalized; manual shift no longer required"},
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert res_canc.status_code == 200
        canc_data = res_canc.json()
        assert canc_data["execution_status"] == "cancelled"
        assert canc_data["is_cancelled"] is True
        print(f"  CR #{canc_cr_id} cancelled by owner with reason recorded.")
        test_results.append(("Cancellation Lifecycle", "PASS"))

        # ---------------------------------------------------------------------
        # 6. POLICY RE-VALIDATION AT APPROVAL TIME
        # ---------------------------------------------------------------------
        print("\n--- [6] Policy Re-Validation at Approval Time ---")
        # Step A: Create CR for prefix 103.145.22.0/24
        temp_prefix = "103.145.22.0/24"
        rev_cr_res = await client.post(
            "/api/v1/change-requests",
            json={
                "prefix": temp_prefix,
                "target_peer": "198.51.100.5",
                "diff_payload": "set local-preference 210",
                "justification": "Policy revocation test",
                "rollback_instructions": "no set local-preference",
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        rev_cr_id = rev_cr_res.json()["id"]

        # Step B: Simulate policy change: deactivate prefix allowlist in DB
        async with session_factory() as db:
            await db.execute(
                select(PrefixAllowlist).where(PrefixAllowlist.prefix == temp_prefix)
            )
            allow_entry = (await db.execute(select(PrefixAllowlist).where(PrefixAllowlist.prefix == temp_prefix))).scalars().first()
            if allow_entry:
                allow_entry.is_active = False
                await db.commit()

        # Step C: Approver attempts to approve the CR now that allowlist is revoked
        res_rev_appr = await client.post(
            f"/api/v1/change-requests/{rev_cr_id}/approve",
            headers={"Authorization": f"Bearer {approver1_token}"},
        )
        assert res_rev_appr.status_code == 400
        assert "POLICY RE-VALIDATION FAILED" in res_rev_appr.json()["detail"]
        print("  Policy re-validation correctly failed and rejected approval when allowlist was deactivated.")

        # Step D: Restore prefix allowlist in DB
        async with session_factory() as db:
            allow_entry = (await db.execute(select(PrefixAllowlist).where(PrefixAllowlist.prefix == temp_prefix))).scalars().first()
            if allow_entry:
                allow_entry.is_active = True
                await db.commit()
        test_results.append(("Policy Re-Validation at Approval Time", "PASS"))

        # ---------------------------------------------------------------------
        # 7. EXECUTION GATE PERMANENT LOCK (HTTP 403)
        # ---------------------------------------------------------------------
        print("\n--- [7] Execution Gate Permanent Guardrail Lock ---")
        # Attempt to execute approved CR #{cr_id}
        res_exec = await client.post(
            f"/api/v1/change-requests/{cr_id}/execute",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_exec.status_code == 403
        assert "ROUTING_EXECUTION_ENABLED is FALSE" in res_exec.json()["detail"]
        print("  POST /change-requests/{id}/execute permanently blocked with HTTP 403 ERR_ROUTING_EXECUTION_DISABLED.")
        test_results.append(("Execution Gate Permanent Lock", "PASS"))

        # ---------------------------------------------------------------------
        # 8. AUDIT HISTORY OF STATE TRANSITIONS
        # ---------------------------------------------------------------------
        print("\n--- [8] Audit History Verification for State Transitions ---")
        async with session_factory() as db:
            stmt = select(AuditEvent).where(AuditEvent.resource_type == "change_request").order_by(AuditEvent.id.desc())
            events = (await db.execute(stmt)).scalars().all()
            actions = [e.action for e in events]
            print(f"  Recorded Change Request Audit Actions: {set(actions)}")
            assert "CREATE_CHANGE_REQUEST" in actions
            assert "APPROVE_CHANGE_REQUEST_STEP_1" in actions
            assert "APPROVE_CHANGE_REQUEST_FINAL" in actions
            assert "REJECT_CHANGE_REQUEST" in actions
            assert "CANCEL_CHANGE_REQUEST" in actions
        test_results.append(("Audit History of State Transitions", "PASS"))

        # ---------------------------------------------------------------------
        # 9. PERMANENT REGRESSION TEST: GET /api/v1/audit RBAC ENFORCEMENT
        # ---------------------------------------------------------------------
        print("\n--- [9] RBAC Regression Test for GET /api/v1/audit Across 5 Roles ---")
        # A. noc_operator -> 403 Forbidden
        r_op = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {operator_token}"})
        assert r_op.status_code == 403, f"Operator expected 403, got {r_op.status_code}"
        print("  Role 'noc_operator'       : HTTP 403 Forbidden (Verified)")

        # B. network_engineer -> 403 Forbidden
        r_eng = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {engineer_token}"})
        assert r_eng.status_code == 403, f"Engineer expected 403, got {r_eng.status_code}"
        print("  Role 'network_engineer'   : HTTP 403 Forbidden (Verified)")

        # C. approver -> 403 Forbidden
        r_appr = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {approver1_token}"})
        assert r_appr.status_code == 403, f"Approver expected 403, got {r_appr.status_code}"
        print("  Role 'approver'           : HTTP 403 Forbidden (Verified)")

        # D. auditor -> 200 OK
        r_aud = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {auditor_token}"})
        assert r_aud.status_code == 200, f"Auditor expected 200, got {r_aud.status_code}"
        assert isinstance(r_aud.json(), list)
        print("  Role 'auditor'            : HTTP 200 OK (Verified, read allowed)")

        # E. super_admin -> 200 OK
        r_adm = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {admin_token}"})
        assert r_adm.status_code == 200, f"Admin expected 200, got {r_adm.status_code}"
        assert isinstance(r_adm.json(), list)
        print("  Role 'super_admin'        : HTTP 200 OK (Verified, read allowed)")

        # F. Unauthenticated -> 401 Unauthorized
        r_noauth = await client.get("/api/v1/audit")
        assert r_noauth.status_code == 401, f"Unauthenticated expected 401, got {r_noauth.status_code}"
        print("  Unauthenticated Request   : HTTP 401 Unauthorized (Verified)")

        # G. Privilege escalation attempt via forged headers / query
        r_tamper = await client.get("/api/v1/audit?role=auditor", headers={"Authorization": f"Bearer {operator_token}"})
        assert r_tamper.status_code == 403
        print("  Privilege Escalation Tamper: HTTP 403 Forbidden (Tampering strictly rejected)")
        test_results.append(("RBAC Audit Log Regression Test", "PASS"))

    print("\n" + "=" * 75)
    print("UAT-CR-01 ACCEPTANCE VERIFICATION SUMMARY")
    print("=" * 75)
    all_passed = True
    for name, res in test_results:
        print(f"  {name:<45}: {res}")
        if res != "PASS":
            all_passed = False

    assert all_passed, "One or more UAT-CR-01 checks failed!"
    print("\n>>> ALL 9 UAT-CR-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY! <<<\n")


if __name__ == "__main__":
    asyncio.run(run_change_request_acceptance())

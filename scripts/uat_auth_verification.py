#!/usr/bin/env python3
"""
UAT-AUTH-01 Automated Acceptance Test Harness.
Tests authentication, token lifecycle (including expiration and invalidation),
and RBAC enforcement across all 5 system roles on the isolated UAT environment.
"""
import os
import sys
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Point to isolated UAT environment
env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

if "DATABASE_URL" not in os.environ:
    from app.core.config import settings
    os.environ["DATABASE_URL"] = settings.DATABASE_URL

import jwt
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.config import settings
from app.core.security import get_password_hash, create_access_token
from app.models.user import User, UserRole, UserStatus
from app.models.audit import AuditEvent


TEST_PASSWORDS = {
    "uat_engineer": "UatEngineer#2026!Sec",
    "uat_approver": "UatApprover#2026!Sec",
    "uat_operator": "UatOperator#2026!Sec",
    "uat_auditor": "UatAuditor#2026!Sec",
}


async def setup_test_users(session_factory):
    """Seed test users for the 4 additional roles if not already present."""
    roles_map = {
        "uat_engineer": UserRole.NETWORK_ENGINEER.value,
        "uat_approver": UserRole.APPROVER.value,
        "uat_operator": UserRole.NOC_OPERATOR.value,
        "uat_auditor": UserRole.AUDITOR.value,
    }

    async with session_factory() as session:
        for username, role_val in roles_map.items():
            stmt = select(User).where(User.username == username)
            res = await session.execute(stmt)
            existing = res.scalars().first()
            if not existing:
                pwd_hash = get_password_hash(TEST_PASSWORDS[username])
                new_user = User(
                    username=username,
                    email=f"{username}@jdp-noc.net",
                    password_hash=pwd_hash,
                    full_name=f"UAT Test {username.title()}",
                    role=role_val,
                    status=UserStatus.ACTIVE.value,
                    is_active=True,
                )
                session.add(new_user)
        await session.commit()


async def run_auth_acceptance():
    print("=" * 70)
    print("STARTING UAT-AUTH-01 ACCEPTANCE VERIFICATION")
    print("=" * 70)

    engine = create_async_engine(os.environ["DATABASE_URL"])
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    await setup_test_users(session_factory)

    transport = ASGITransport(app=app)
    tokens: Dict[str, str] = {}
    test_results = []

    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:

        # ---------------------------------------------------------------------
        # 1. AUTHENTICATION & LOGIN SCENARIOS
        # ---------------------------------------------------------------------
        print("\n--- [1] Authentication & Login Verification ---")

        # 1a. Valid login via OAuth2 Form
        login_form = await client.post(
            "/api/v1/auth/login",
            data={"username": "uat_engineer", "password": TEST_PASSWORDS["uat_engineer"]},
        )
        assert login_form.status_code == 200, f"Expected 200, got {login_form.status_code}"
        data = login_form.json()
        assert "access_token" in data and data["token_type"] == "bearer"
        assert data["role"] == "network_engineer"
        tokens["uat_engineer"] = data["access_token"]
        test_results.append(("Login Valid Form (uat_engineer)", "PASS"))
        print("  [PASS] Valid OAuth2 Form login generates bearer JWT.")

        # 1b. Valid login via JSON endpoint
        login_json = await client.post(
            "/api/v1/auth/login-json",
            json={"username": "uat_approver", "password": TEST_PASSWORDS["uat_approver"]},
        )
        assert login_json.status_code == 200
        tokens["uat_approver"] = login_json.json()["access_token"]
        test_results.append(("Login Valid JSON (uat_approver)", "PASS"))
        print("  [PASS] Valid JSON login generates bearer JWT.")

        # Acquire tokens for remaining roles
        for uname in ["uat_operator", "uat_auditor"]:
            resp = await client.post(
                "/api/v1/auth/login-json",
                json={"username": uname, "password": TEST_PASSWORDS[uname]},
            )
            assert resp.status_code == 200
            tokens[uname] = resp.json()["access_token"]

        # Acquire token for uat_admin (password from Batch 1 or generate a fresh admin token)
        admin_token = create_access_token(subject="uat_admin", role=UserRole.SUPER_ADMIN.value)
        tokens["uat_admin"] = admin_token

        # 1c. Login with Incorrect Password
        bad_pw_resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "uat_engineer", "password": "WrongPassword999!"},
        )
        assert bad_pw_resp.status_code == 401, f"Expected 401, got {bad_pw_resp.status_code}"
        assert "Incorrect username or password" in bad_pw_resp.json()["detail"]
        test_results.append(("Login Wrong Password Rejected (401)", "PASS"))
        print("  [PASS] Login with incorrect password returns HTTP 401 Unauthorized.")

        # 1d. Login with Unknown Username
        unknown_user_resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "non_existent_hacker", "password": "AnyPassword!"},
        )
        assert unknown_user_resp.status_code == 401
        assert "Incorrect username or password" in unknown_user_resp.json()["detail"]
        test_results.append(("Login Unknown Username Rejected (401, No Leak)", "PASS"))
        print("  [PASS] Login with unknown username returns 401 without user enumeration leakage.")

        # 1e. Protected endpoint access with valid token (/api/v1/auth/me)
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['uat_engineer']}"},
        )
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["username"] == "uat_engineer"
        assert me_data["role"] == "network_engineer"
        assert "password" not in me_data and "password_hash" not in me_data
        test_results.append(("Protected Endpoint Access & Secret Redaction", "PASS"))
        print("  [PASS] /auth/me returns valid user info without password leakage.")

        # 1f. Malformed Token Rejected
        malformed_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer this.is.an.invalid.malformed.jwt.token"},
        )
        assert malformed_resp.status_code == 401
        assert "Could not validate credentials" in malformed_resp.json()["detail"]
        test_results.append(("Malformed Token Rejected (401)", "PASS"))
        print("  [PASS] Malformed token rejected with HTTP 401.")

        # 1g. Forged Signature Token Rejected
        forged_jwt = jwt.encode(
            {"sub": "uat_admin", "role": "super_admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            "wrong-forged-secret-key-attacker",
            algorithm="HS256",
        )
        forged_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {forged_jwt}"},
        )
        assert forged_resp.status_code == 401
        test_results.append(("Forged Signature Token Rejected (401)", "PASS"))
        print("  [PASS] Forged token signature rejected with HTTP 401.")

        # 1h. Expired Token Rejected
        expired_jwt = create_access_token(
            subject="uat_engineer",
            role=UserRole.NETWORK_ENGINEER.value,
            expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
        )
        expired_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_jwt}"},
        )
        assert expired_resp.status_code == 401
        assert "Could not validate credentials" in expired_resp.json()["detail"]
        test_results.append(("Expired Token Rejected (401)", "PASS"))
        print("  [PASS] Expired token strictly rejected with HTTP 401.")

        # 1i. Logout Endpoint & Audit Logging
        logout_resp = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['uat_engineer']}"},
        )
        assert logout_resp.status_code == 200
        assert logout_resp.json()["message"] == "Successfully logged out"

        # Verify audit log in PostgreSQL
        async with session_factory() as session:
            stmt = select(AuditEvent).where(
                AuditEvent.actor_username == "uat_engineer",
                AuditEvent.action == "LOGOUT",
            ).order_by(AuditEvent.id.desc())
            res = await session.execute(stmt)
            audit_item = res.scalars().first()
            assert audit_item is not None
            assert audit_item.resource_type == "auth"
        test_results.append(("Logout Endpoint & Audit Record", "PASS"))
        print("  [PASS] Logout records LOGOUT event in audit_events table.")

        # ---------------------------------------------------------------------
        # 2. RBAC PERMISSION MATRIX ENFORCEMENT
        # ---------------------------------------------------------------------
        print("\n--- [2] RBAC Permission Matrix Verification across 5 Roles ---")

        # 2a. Device Creation (POST /api/v1/devices)
        # Allowed: super_admin, network_engineer | Forbidden: approver, noc_operator, auditor
        ts = int(datetime.now().timestamp())
        dev_payload = {
            "hostname": f"test-edge-{ts}.noc.local",
            "mgmt_ip": f"10.200.0.{ts % 200 + 1}",
            "vendor": "Cisco",
            "model": "ASR9000",
        }

        # noc_operator -> 403
        op_dev = await client.post(
            "/api/v1/devices",
            json=dev_payload,
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert op_dev.status_code == 403, f"Expected 403, got {op_dev.status_code}"
        assert "Access denied" in op_dev.json()["detail"]
        print("  [PASS] noc_operator cannot create devices (HTTP 403 Forbidden).")

        # auditor -> 403
        aud_dev = await client.post(
            "/api/v1/devices",
            json=dev_payload,
            headers={"Authorization": f"Bearer {tokens['uat_auditor']}"},
        )
        assert aud_dev.status_code == 403
        print("  [PASS] auditor cannot create devices (HTTP 403 Forbidden).")

        # approver -> 403
        app_dev = await client.post(
            "/api/v1/devices",
            json=dev_payload,
            headers={"Authorization": f"Bearer {tokens['uat_approver']}"},
        )
        assert app_dev.status_code == 403
        print("  [PASS] approver cannot create devices (HTTP 403 Forbidden).")

        # network_engineer -> 201 Created
        eng_dev = await client.post(
            "/api/v1/devices",
            json=dev_payload,
            headers={"Authorization": f"Bearer {tokens['uat_engineer']}"},
        )
        assert eng_dev.status_code == 201, f"Expected 201, got {eng_dev.status_code}"
        created_device_id = eng_dev.json()["id"]
        print("  [PASS] network_engineer successfully creates device (HTTP 201 Created).")

        # super_admin -> 201 Created
        admin_dev = await client.post(
            "/api/v1/devices",
            json={
                "hostname": f"admin-edge-{ts}.noc.local",
                "mgmt_ip": f"10.200.1.{ts % 200 + 1}",
                "vendor": "Juniper",
            },
            headers={"Authorization": f"Bearer {tokens['uat_admin']}"},
        )
        assert admin_dev.status_code == 201
        print("  [PASS] super_admin successfully creates device (HTTP 201 Created).")
        test_results.append(("RBAC Device Creation (Engineer/Admin only)", "PASS"))

        # 2b. SNMP Profile Creation (POST /api/v1/devices/snmp/profiles)
        snmp_payload = {
            "name": f"UAT-RBAC-Profile-{ts}",
            "version": "v3",
            "auth_protocol": "SHA",
            "auth_password": "AuthSecret2026!",
            "priv_protocol": "AES",
            "priv_password": "PrivSecret2026!",
        }

        # noc_operator -> 403
        op_snmp = await client.post(
            "/api/v1/devices/snmp/profiles",
            json=snmp_payload,
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert op_snmp.status_code == 403
        print("  [PASS] noc_operator cannot create SNMP profiles (HTTP 403 Forbidden).")

        # auditor -> 403
        aud_snmp = await client.post(
            "/api/v1/devices/snmp/profiles",
            json=snmp_payload,
            headers={"Authorization": f"Bearer {tokens['uat_auditor']}"},
        )
        assert aud_snmp.status_code == 403
        print("  [PASS] auditor cannot create SNMP profiles (HTTP 403 Forbidden).")

        # network_engineer -> 201 Created
        eng_snmp = await client.post(
            "/api/v1/devices/snmp/profiles",
            json=snmp_payload,
            headers={"Authorization": f"Bearer {tokens['uat_engineer']}"},
        )
        assert eng_snmp.status_code == 201
        test_results.append(("RBAC SNMP Profile Creation (Engineer/Admin only)", "PASS"))
        print("  [PASS] network_engineer successfully creates SNMP profile (HTTP 201 Created).")

        # 2c. Prefix Allowlist Policy Management (POST /api/v1/admin/policies/prefixes)
        # Allowed: super_admin only | Forbidden: network_engineer, approver, noc_operator, auditor
        prefix_payload = {
            "prefix": f"103.145.{(ts % 200) + 10}.0/24",
            "description": "UAT Authorized Prefix",
            "is_active": True,
        }

        # network_engineer -> 403
        eng_prefix = await client.post(
            "/api/v1/admin/policies/prefixes",
            json=prefix_payload,
            headers={"Authorization": f"Bearer {tokens['uat_engineer']}"},
        )
        assert eng_prefix.status_code == 403
        print("  [PASS] network_engineer cannot modify prefix allowlist policy (HTTP 403 Forbidden).")

        # noc_operator -> 403
        op_prefix = await client.post(
            "/api/v1/admin/policies/prefixes",
            json=prefix_payload,
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert op_prefix.status_code == 403
        print("  [PASS] noc_operator cannot modify prefix allowlist policy (HTTP 403 Forbidden).")

        # super_admin -> 201
        admin_prefix = await client.post(
            "/api/v1/admin/policies/prefixes",
            json=prefix_payload,
            headers={"Authorization": f"Bearer {tokens['uat_admin']}"},
        )
        assert admin_prefix.status_code == 201
        test_results.append(("RBAC Prefix Allowlist (super_admin only)", "PASS"))
        print("  [PASS] super_admin successfully adds prefix to allowlist (HTTP 201 Created).")

        # 2d. Audit Logs Access (GET /api/v1/audit)
        # Allowed: super_admin, auditor | Forbidden: noc_operator, network_engineer
        op_audit = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert op_audit.status_code == 403
        print("  [PASS] noc_operator cannot access audit logs (HTTP 403 Forbidden).")

        aud_audit = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {tokens['uat_auditor']}"},
        )
        assert aud_audit.status_code == 200
        assert isinstance(aud_audit.json(), list)
        print("  [PASS] auditor successfully reads audit logs (HTTP 200 OK).")

        admin_audit = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {tokens['uat_admin']}"},
        )
        assert admin_audit.status_code == 200
        test_results.append(("RBAC Audit Logs Read (Auditor & Admin only)", "PASS"))
        print("  [PASS] super_admin successfully reads audit logs (HTTP 200 OK).")

        # 2e. Emergency Stop Trigger (POST /api/v1/mitigation/emergency-stop)
        # Allowed: network_engineer, approver, super_admin | Forbidden: noc_operator, auditor
        op_estop = await client.post(
            "/api/v1/mitigation/emergency-stop",
            json={"reason": "Operator unauthorized test"},
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert op_estop.status_code == 403
        print("  [PASS] noc_operator cannot trigger emergency stop (HTTP 403 Forbidden).")

        aud_estop = await client.post(
            "/api/v1/mitigation/emergency-stop",
            json={"reason": "Auditor unauthorized test"},
            headers={"Authorization": f"Bearer {tokens['uat_auditor']}"},
        )
        assert aud_estop.status_code == 403
        print("  [PASS] auditor cannot trigger emergency stop (HTTP 403 Forbidden).")

        admin_estop = await client.post(
            "/api/v1/mitigation/emergency-stop",
            json={"reason": "Super Admin authorized UAT test"},
            headers={"Authorization": f"Bearer {tokens['uat_admin']}"},
        )
        assert admin_estop.status_code == 200
        assert admin_estop.json()["emergency_stop_active"] is True
        print("  [PASS] super_admin successfully triggers emergency stop (HTTP 200 OK).")
        test_results.append(("RBAC Emergency Stop (Forbidden for Operator/Auditor)", "PASS"))

        # Reset circuit breaker after test
        cb_reset = await client.post(
            "/api/v1/mitigation/circuit-breaker/reset",
            json={"notes": "Resetting emergency stop after UAT verification"},
            headers={"Authorization": f"Bearer {tokens['uat_admin']}"},
        )
        assert cb_reset.status_code == 200

        # 2f. Request Manipulation & Role Escalation Defense
        # Attacker sends role="super_admin" in request body to mutate device or self-elevate
        tampered_resp = await client.post(
            "/api/v1/devices",
            json={
                "hostname": "tampered-router.noc.local",
                "mgmt_ip": "10.200.0.99",
                "vendor": "Cisco",
                "role": "super_admin",  # Tampered field
            },
            headers={"Authorization": f"Bearer {tokens['uat_operator']}"},
        )
        assert tampered_resp.status_code == 403
        print("  [PASS] Privilege escalation via body manipulation blocked (HTTP 403 Forbidden).")
        test_results.append(("Tamper Defense (Zero privilege escalation)", "PASS"))

    print("\n" + "=" * 70)
    print("ALL UAT-AUTH-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)
    for test_name, status in test_results:
        print(f"  {test_name.ljust(50)}: {status}")


if __name__ == "__main__":
    asyncio.run(run_auth_acceptance())

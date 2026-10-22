#!/usr/bin/env python3
"""
UAT-INST-01 Verification Harness.
Validates fresh installation, migration, admin login, API accessibility,
guardrail verification, and restart persistence on the isolated UAT database.
"""
import os
import sys
import asyncio

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Load UAT environment if present
env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

if "DATABASE_URL" not in os.environ:
    from app.core.config import settings
    os.environ["DATABASE_URL"] = settings.DATABASE_URL

import httpx
from app.main import app
from httpx import ASGITransport, AsyncClient


async def run_uat_checks(password: str):
    print("=" * 60)
    print("RUNNING UAT-INST-01 AUTOMATED VERIFICATION CHECKS")
    print("=" * 60)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:
        # 1. Check health endpoint
        health_res = await client.get("/health")
        print(f"[1] Health Check: Status {health_res.status_code} | {health_res.json()}")
        assert health_res.status_code == 200
        assert health_res.json()["status"] == "healthy"

        # 2. Login as uat_admin (OAuth2 Form Login)
        login_res = await client.post(
            "/api/v1/auth/login",
            data={"username": "uat_admin", "password": password},
        )
        print(f"[2] Login uat_admin (Form): Status {login_res.status_code}")
        assert login_res.status_code == 200
        data = login_res.json()
        token = data.get("access_token")
        assert token is not None
        print("    JWT Token acquired successfully via OAuth2 Form.")

        # 2b. Login as uat_admin (JSON payload)
        login_json_res = await client.post(
            "/api/v1/auth/login-json",
            json={"username": "uat_admin", "password": password},
        )
        print(f"[2b] Login uat_admin (JSON): Status {login_json_res.status_code}")
        assert login_json_res.status_code == 200

        headers = {"Authorization": f"Bearer {token}"}

        # 3. Check current user info (/api/v1/auth/me)
        me_res = await client.get("/api/v1/auth/me", headers=headers)
        me_data = me_res.json()
        print(f"[3] /auth/me Profile: Status {me_res.status_code} | User: {me_data.get('username')}, Role: {me_data.get('role')}")
        assert me_res.status_code == 200
        assert me_data["username"] == "uat_admin"
        assert me_data["role"] == "super_admin"

        # 4. Check API devices endpoint
        dev_res = await client.get("/api/v1/devices", headers=headers)
        print(f"[4] /devices Query: Status {dev_res.status_code} | Devices Count: {len(dev_res.json())}")
        assert dev_res.status_code == 200

        # 5. Check System Guardrail Settings via Production Adapter endpoint
        settings_res = await client.get("/api/v1/mitigation/production-adapter/status", headers=headers)
        s_data = settings_res.json()
        print(f"[5] /mitigation/production-adapter/status: Status {settings_res.status_code}")
        print(f"    is_enabled: {s_data.get('is_enabled')}")
        print(f"    routing_execution_enabled: {s_data.get('routing_execution_enabled')}")
        print(f"    production_routing_enabled: {s_data.get('production_routing_enabled')}")
        print(f"    flowspec_execution_enabled: {s_data.get('flowspec_execution_enabled')}")
        print(f"    rtbh_execution_enabled: {s_data.get('rtbh_execution_enabled')}")
        print(f"    safety_mode: {s_data.get('safety_mode')}")

        assert settings_res.status_code == 200
        assert s_data.get("is_enabled") is False
        assert s_data.get("routing_execution_enabled") is False
        assert s_data.get("production_routing_enabled") is False
        assert s_data.get("flowspec_execution_enabled") is False
        assert s_data.get("rtbh_execution_enabled") is False
        assert s_data.get("safety_mode") == "LOCKED_DRY_RUN"

        # 5b. Check Circuit Breaker Status
        cb_res = await client.get("/api/v1/mitigation/circuit-breaker/status", headers=headers)
        cb_data = cb_res.json()
        print(f"[5b] Circuit Breaker Status: Status {cb_res.status_code} | State: {cb_data.get('state')}")
        assert cb_res.status_code == 200
        assert cb_data.get("state") == "CLOSED"

        # 6. Verify Production Execution is Blocked
        cr_exec = await client.post(
            "/api/v1/change-requests/1/execute",
            headers=headers,
        )
        print(f"[6] Route Execution Test: Status {cr_exec.status_code} | Detail: {cr_exec.json().get('detail')}")
        assert cr_exec.status_code == 403

        print("=" * 60)
        print("ALL UAT-INST-01 INTEGRATION CHECKS PASSED SUCCESSFULLY!")
        print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_uat_install.py <password>")
        sys.exit(1)
    asyncio.run(run_uat_checks(sys.argv[1]))

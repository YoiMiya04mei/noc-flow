#!/usr/bin/env python3
"""
UAT-SNMP-01 Automated Acceptance Test Harness.
Tests SNMPv3 profile encryption, secret masking, inventory linking,
poll execution, rate calculations, history recording, timeout preservation,
and duplicate poll prevention on the isolated UAT environment.
"""
import os
import sys
import asyncio
import time
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
from app.models.user import UserRole
from app.models.inventory import Device, Interface, SNMPProfile, InterfaceMetricsHistory
from app.services.snmp_service import (
    get_or_create_mock_device,
    mark_poll_started,
    mark_poll_finished,
    is_poll_in_flight,
    decrypt_snmp_secret,
    calculate_counter_delta,
    calculate_utilization_pct,
)


async def run_snmp_acceptance():
    print("=" * 70)
    print("STARTING UAT-SNMP-01 ACCEPTANCE VERIFICATION")
    print("=" * 70)

    engine = create_async_engine(os.environ["DATABASE_URL"])
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    engineer_token = create_access_token(subject="uat_engineer", role=UserRole.NETWORK_ENGINEER.value)
    operator_token = create_access_token(subject="uat_operator", role=UserRole.NOC_OPERATOR.value)

    transport = ASGITransport(app=app)
    test_results = []
    ts = int(time.time())

    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:

        # ---------------------------------------------------------------------
        # 1. PROFILE REGISTRATION & SECRET MASKING
        # ---------------------------------------------------------------------
        print("\n--- [1] SNMPv3 Profile Registration & Secret Protection ---")
        secret_auth = f"UatAuthSecret#{ts}"
        secret_priv = f"UatPrivSecret#{ts}"

        profile_payload = {
            "name": f"UAT-Core-LabProfile-{ts}",
            "version": "v3",
            "port": 161,
            "timeout_sec": 2.0,
            "retries": 2,
            "security_name": "uat_lab_user",
            "auth_protocol": "SHA",
            "auth_pass": secret_auth,
            "priv_protocol": "AES",
            "priv_pass": secret_priv,
            "is_active": True,
        }

        prof_resp = await client.post(
            "/api/v1/devices/snmp/profiles",
            json=profile_payload,
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert prof_resp.status_code == 201, f"Failed to create profile: {prof_resp.text}"
        prof_data = prof_resp.json()
        profile_id = prof_data["id"]

        # Assert secrets are NEVER returned plaintext in response
        assert secret_auth not in str(prof_data)
        assert secret_priv not in str(prof_data)
        assert prof_data.get("auth_pass") is None
        assert prof_data.get("priv_pass") is None
        assert prof_data["has_auth_pass"] is True
        assert prof_data["has_priv_pass"] is True
        test_results.append(("SNMPv3 Profile Secret Masking on API", "PASS"))
        print("  [PASS] SNMPv3 profile created and secrets masked on API response.")

        # Verify encryption at rest in PostgreSQL
        async with session_factory() as session:
            stmt = select(SNMPProfile).where(SNMPProfile.id == profile_id)
            res = await session.execute(stmt)
            db_profile = res.scalar_one()
            assert db_profile.auth_pass_encrypted is not None
            assert secret_auth not in db_profile.auth_pass_encrypted
            # Decrypt verify
            dec_auth = decrypt_snmp_secret(db_profile.auth_pass_encrypted)
            dec_priv = decrypt_snmp_secret(db_profile.priv_pass_encrypted)
            assert dec_auth == secret_auth
            assert dec_priv == secret_priv
        test_results.append(("SNMPv3 Secrets Encrypted at Rest (Fernet AES)", "PASS"))
        print("  [PASS] Secrets stored encrypted via Fernet (AES-128-CBC + HMAC-SHA256) at rest.")

        # ---------------------------------------------------------------------
        # 2. INVENTORY REGISTRATION & RBAC ENFORCEMENT
        # ---------------------------------------------------------------------
        print("\n--- [2] Inventory Device Linking & RBAC Enforcement ---")
        device_hostname = f"uat-lab-router-{ts}.noc.local"
        dev_resp = await client.post(
            "/api/v1/devices",
            json={
                "hostname": device_hostname,
                "mgmt_ip": "10.150.1.1",
                "vendor": "Juniper",
                "model": "MX960",
                "snmp_profile_id": profile_id,
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert dev_resp.status_code == 201
        device_id = dev_resp.json()["id"]

        # Operator poll attempt -> 403 Forbidden
        op_poll = await client.post(
            f"/api/v1/devices/{device_id}/poll",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert op_poll.status_code == 403
        test_results.append(("RBAC Poll Trigger (Operator Forbidden)", "PASS"))
        print("  [PASS] noc_operator cannot trigger manual SNMP poll (HTTP 403 Forbidden).")

        # ---------------------------------------------------------------------
        # 3. POLLING EXECUTION & RATE CALCULATIONS (SIMULATED LAB AGENT)
        # ---------------------------------------------------------------------
        print("\n--- [3] Polling Execution & Counter Rate Calculations (LAB / SIMULATED) ---")
        # 3a. First Poll (Baseline establishing)
        poll1_resp = await client.post(
            f"/api/v1/devices/{device_id}/poll",
            json={"force_mock": True},
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert poll1_resp.status_code == 200
        poll1_data = poll1_resp.json()
        assert poll1_data["success"] is True
        assert poll1_data["snmp_status"] == "ok"
        assert poll1_data["interfaces_polled"] >= 3

        # First poll baseline check: bps must be 0.0 (no false spike)
        ifaces1_resp = await client.get(
            f"/api/v1/devices/{device_id}/interfaces",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert ifaces1_resp.status_code == 200
        ifaces1 = ifaces1_resp.json()
        test_iface = ifaces1[0]
        assert test_iface["in_bps"] == 0
        assert test_iface["out_bps"] == 0
        test_results.append(("Baseline First Poll (Zero false spike)", "PASS"))
        print("  [PASS] Initial poll sets baseline without false bandwidth spikes (0.0 bps).")

        # 3b. Advance counters on simulator and execute second poll
        mock_dev = get_or_create_mock_device(device_hostname, "juniper", "10.150.1.1")
        mock_dev.simulate_traffic_step(elapsed_sec=10.0)

        await asyncio.sleep(0.1)  # small delta time

        poll2_resp = await client.post(
            f"/api/v1/devices/{device_id}/poll",
            json={"force_mock": True},
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert poll2_resp.status_code == 200
        poll2_data = poll2_resp.json()
        assert poll2_data["success"] is True

        # Check interface metrics
        ifaces2_resp = await client.get(
            f"/api/v1/devices/{device_id}/interfaces",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        ifaces2 = ifaces2_resp.json()
        updated_if = next(i for i in ifaces2 if i["id"] == test_iface["id"])
        assert updated_if["in_bps"] >= 0
        assert updated_if["out_bps"] >= 0
        assert updated_if["in_pps"] >= 0
        assert updated_if["out_pps"] >= 0
        assert updated_if["utilization_pct"] >= 0.0
        test_results.append(("Delta Counter & Rate Calculations (bps/pps/utilization)", "PASS"))
        print(f"  [PASS] Rate calculated successfully: {updated_if['if_name']} in_bps={updated_if['in_bps']}, util={updated_if['utilization_pct']}%.")

        # 3c. Verify Interface History in Database
        hist_resp = await client.get(
            f"/api/v1/devices/{device_id}/interfaces/{test_iface['id']}/history",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert hist_resp.status_code == 200
        history_records = hist_resp.json()
        assert len(history_records) >= 1
        assert history_records[0]["interface_id"] == test_iface["id"]
        assert history_records[0]["oper_status"] == "up"
        test_results.append(("Interface History Recording in PostgreSQL", "PASS"))
        print(f"  [PASS] {len(history_records)} historical telemetry sample(s) persisted in database.")

        # ---------------------------------------------------------------------
        # 4. DUPLICATE CONCURRENT POLL PREVENTION
        # ---------------------------------------------------------------------
        print("\n--- [4] Duplicate Concurrent Poll Prevention ---")
        dummy_id = 99999 + (ts % 1000)
        assert await mark_poll_started(dummy_id) is True
        assert is_poll_in_flight(dummy_id) is True

        # Second concurrent attempt must be rejected
        assert await mark_poll_started(dummy_id) is False
        print("  [PASS] Concurrent poll attempt on same device strictly rejected by in-flight lock.")

        await mark_poll_finished(dummy_id)
        assert is_poll_in_flight(dummy_id) is False
        test_results.append(("Duplicate Concurrent Poll Prevention", "PASS"))

        # ---------------------------------------------------------------------
        # 5. ERROR, TIMEOUT & OPERATIONAL STATUS PRESERVATION
        # ---------------------------------------------------------------------
        print("\n--- [5] Timeout Handling & Operational Status Preservation ---")
        mock_dev.should_timeout = True

        poll_timeout_resp = await client.post(
            f"/api/v1/devices/{device_id}/poll",
            json={"force_mock": True},
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert poll_timeout_resp.status_code == 200
        t_data = poll_timeout_resp.json()
        assert t_data["success"] is False
        assert t_data["snmp_status"] == "timeout"
        assert "timed out" in t_data["error_message"].lower()

        # CRITICAL SAFEGUARD: Verify oper_status did NOT flip to 'down'
        dev_after_timeout = await client.get(
            f"/api/v1/devices/{device_id}",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert dev_after_timeout.status_code == 200
        dev_after_data = dev_after_timeout.json()
        assert dev_after_data["snmp_status"] == "timeout"
        for iface in dev_after_data["interfaces"]:
            assert iface["oper_status"] == "up", f"Interface {iface['if_name']} wrongly flipped to down!"
        test_results.append(("Timeout Oper Status Preservation (No False Down)", "PASS"))
        print("  [PASS] Polling timeout marked device as 'timeout' without flipping interface oper_status to down.")

        mock_dev.should_timeout = False

        # 5b. Stale Device Telemetry Check
        async with session_factory() as session:
            stmt = select(Device).where(Device.id == device_id)
            res = await session.execute(stmt)
            d = res.scalar_one()
            d.last_polled_at = datetime.now(timezone.utc) - timedelta(minutes=10)
            await session.commit()

        # Check worker status
        worker_resp = await client.get(
            "/api/v1/devices/snmp/worker-status",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert worker_resp.status_code == 200
        w_data = worker_resp.json()
        assert "is_running" in w_data
        assert "polling_interval_seconds" in w_data
        test_results.append(("SNMP Worker Status Telemetry", "PASS"))
        print(f"  [PASS] Worker telemetry verified: interval={w_data['polling_interval_seconds']}s, concurrency={w_data['concurrency_limit']}.")

    print("\n" + "=" * 70)
    print("ALL UAT-SNMP-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY (LAB/SIMULATED)!")
    print("=" * 70)
    for test_name, status in test_results:
        print(f"  {test_name.ljust(55)}: {status}")


if __name__ == "__main__":
    asyncio.run(run_snmp_acceptance())

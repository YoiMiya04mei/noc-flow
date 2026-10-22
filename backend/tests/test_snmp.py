import pytest
import time
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.inventory import Device, Interface, SNMPProfile, InterfaceMetricsHistory
from app.services.snmp_service import (
    calculate_counter_delta,
    calculate_utilization_pct,
    encrypt_snmp_secret,
    decrypt_snmp_secret,
    get_or_create_mock_device,
    poll_device_metrics,
    MAX_COUNTER64,
)


# =============================================================================
# 1. UNIT TESTS: COUNTER DELTA, REBOOT, WRAP & RATE CALCULATIONS
# =============================================================================

def test_counter_delta_regular_rate():
    """Verify bps and pps rate calculations over regular time intervals."""
    t0 = 1000.0
    t1 = 1010.0 # 10 seconds elapsed
    prev_octets = 100_000_000
    curr_octets = 112_500_000 # 12.5 MB = 100 Megabits in 10s -> 10 Mbps
    
    rate_octets, reboot, anom = calculate_counter_delta(
        curr_val=curr_octets,
        prev_val=prev_octets,
        curr_time=t1,
        prev_time=t0,
        is_64bit=True,
    )
    assert reboot is False
    assert anom is False
    assert rate_octets == 1_250_000.0 # 1.25 MB/s
    bps = rate_octets * 8.0
    assert bps == 10_000_000.0 # Exactly 10 Mbps


def test_counter_delta_pps_calculation():
    """Verify pps calculation."""
    t0 = 100.0
    t1 = 105.0 # 5 seconds
    prev_pkts = 50_000
    curr_pkts = 75_000 # 25,000 pkts in 5s -> 5,000 pps

    pps, reboot, anom = calculate_counter_delta(
        curr_val=curr_pkts,
        prev_val=prev_pkts,
        curr_time=t1,
        prev_time=t0,
    )
    assert reboot is False
    assert anom is False
    assert pps == 5000.0


def test_counter_delta_zero_change():
    """When counter has not changed, rate should be strictly 0."""
    rate, reboot, anom = calculate_counter_delta(
        curr_val=1000,
        prev_val=1000,
        curr_time=10.0,
        prev_time=5.0,
    )
    assert reboot is False
    assert anom is False
    assert rate == 0.0


def test_counter_delta_baseline_first_poll():
    """First poll establishing baseline must return rate 0 without error."""
    rate, reboot, anom = calculate_counter_delta(
        curr_val=1000,
        prev_val=None,
        curr_time=10.0,
        prev_time=None,
    )
    assert rate == 0.0
    assert reboot is False
    assert anom is False


def test_device_reboot_detection_no_spike():
    """
    CRITICAL REQUIREMENT: When sysUpTime drops, device reboot must be detected.
    Counter baseline is reset and rate is 0.0, preventing fake bandwidth spikes.
    """
    t0 = 100.0
    t1 = 110.0
    prev_uptime = 500_000 # 5,000 seconds
    curr_uptime = 1_000   # 10 seconds (rebooted!)
    prev_octets = 50_000_000_000
    curr_octets = 5_000_000 # Counter restarted from small value

    rate, reboot, anom = calculate_counter_delta(
        curr_val=curr_octets,
        prev_val=prev_octets,
        curr_time=t1,
        prev_time=t0,
        curr_uptime=curr_uptime,
        prev_uptime=prev_uptime,
        is_64bit=True,
        speed_bps=10_000_000_000,
    )
    assert reboot is True
    assert anom is False
    assert rate == 0.0 # Strict 0.0, NO FALSE SPIKE


def test_counter_64bit_wrap_valid():
    """
    Verify valid 64-bit counter wrap calculation when device has NOT rebooted.
    """
    t0 = 100.0
    t1 = 110.0 # 10s
    prev_octets = MAX_COUNTER64 - 100_000_000 # Near 2^64
    curr_octets = 150_000_000                 # Wrapped past 0
    uptime = 10_000_000

    rate, reboot, anom = calculate_counter_delta(
        curr_val=curr_octets,
        prev_val=prev_octets,
        curr_time=t1,
        prev_time=t0,
        curr_uptime=uptime + 1000,
        prev_uptime=uptime,
        is_64bit=True,
        speed_bps=10_000_000_000, # 10G link
    )
    assert reboot is False
    assert anom is False
    expected_delta = 250_000_000 + 1
    assert rate == expected_delta / 10.0


def test_counter_reset_anomaly_suppression():
    """
    If counter decreases without uptime reset and resulting rate exceeds 10x capacity,
    it must be flagged as anomaly and suppressed to 0.0.
    """
    t0 = 100.0
    t1 = 110.0 # 10s
    prev_octets = 1_000_000_000
    curr_octets = 500_000_000 # Dropped unexpectedly
    uptime = 10_000_000

    rate, reboot, anom = calculate_counter_delta(
        curr_val=curr_octets,
        prev_val=prev_octets,
        curr_time=t1,
        prev_time=t0,
        curr_uptime=uptime + 1000,
        prev_uptime=uptime,
        is_64bit=True,
        speed_bps=1_000_000_000, # 1G link
    )
    # Wrap formula on 2^64 yields astronomical rate -> flagged as anomaly!
    assert reboot is False
    assert anom is True
    assert rate == 0.0 # Suppressed spike


def test_utilization_calculation():
    """Verify capacity to utilization conversion and unavailable handling."""
    # 5 Gbps on 10 Gbps link -> 50.0%
    util = calculate_utilization_pct(
        in_bps=5_000_000_000,
        out_bps=2_000_000_000,
        speed_bps=10_000_000_000,
    )
    assert util == 50.0

    # Max of in/out used: out is 8 Gbps -> 80.0%
    util = calculate_utilization_pct(
        in_bps=1_000_000_000,
        out_bps=8_000_000_000,
        speed_bps=10_000_000_000,
    )
    assert util == 80.0

    # Link speed missing or zero: returns None (unavailable, never fake 0%)
    assert calculate_utilization_pct(1_000_000, 1_000_000, speed_bps=0) is None
    assert calculate_utilization_pct(1_000_000, 1_000_000, speed_bps=None) is None


# =============================================================================
# 2. CRYPTOGRAPHY & SECRET AT REST TESTS
# =============================================================================

def test_snmp_secret_encryption_and_decryption():
    """Verify Fernet encryption at rest and reversible decryption."""
    original_pass = "NocSuperSecretAuthPrivKey2026!"
    encrypted = encrypt_snmp_secret(original_pass)
    assert encrypted is not None
    assert encrypted != original_pass
    assert "NocSuperSecret" not in encrypted

    decrypted = decrypt_snmp_secret(encrypted)
    assert decrypted == original_pass


# =============================================================================
# 3. RBAC & API ENDPOINT TESTS FOR SNMP PROFILES
# =============================================================================

@pytest.mark.asyncio
async def test_snmp_profile_create_and_secret_masking(client: AsyncClient, engineer_token: str):
    """
    Verify creating an SNMP profile with SNMPv3 authPriv.
    Ensure secrets are NEVER leaked in API response.
    """
    payload = {
        "name": "Juniper-Core-SNMPv3",
        "version": "v3",
        "port": 161,
        "timeout_sec": 2.5,
        "retries": 2,
        "security_name": "jdp_sec_user",
        "auth_protocol": "SHA",
        "auth_pass": "SuperAuthSecret123",
        "priv_protocol": "AES",
        "priv_pass": "SuperPrivSecret456",
        "is_active": True,
    }
    resp = await client.post(
        "/api/v1/devices/snmp/profiles",
        json=payload,
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Juniper-Core-SNMPv3"
    assert data["version"] == "v3"
    assert data["security_name"] == "jdp_sec_user"
    assert data["has_auth_pass"] is True
    assert data["has_priv_pass"] is True

    # ABSOLUTE REQUIREMENT: Secrets must NOT be returned in response!
    assert "SuperAuthSecret123" not in str(data)
    assert "SuperPrivSecret456" not in str(data)
    assert "auth_pass" not in data
    assert "priv_pass" not in data
    assert "auth_pass_encrypted" not in data


@pytest.mark.asyncio
async def test_snmp_profile_rbac_restrictions(
    client: AsyncClient,
    operator_token: str,
    auditor_token: str,
    engineer_token: str,
):
    """
    NOC Operator and Auditor must be forbidden from creating/updating/deleting SNMP profiles.
    Network Engineer must be permitted.
    """
    payload = {
        "name": "Unauthorized-Profile",
        "version": "v2c",
        "community": "public",
    }

    # Operator: 403 Forbidden
    op_resp = await client.post(
        "/api/v1/devices/snmp/profiles",
        json=payload,
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert op_resp.status_code == 403

    # Auditor: 403 Forbidden
    aud_resp = await client.post(
        "/api/v1/devices/snmp/profiles",
        json=payload,
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert aud_resp.status_code == 403

    # Engineer: 201 Created
    eng_resp = await client.post(
        "/api/v1/devices/snmp/profiles",
        json=payload,
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert eng_resp.status_code == 201


# =============================================================================
# 4. DEVICE POLLING, SECURITY GUARDRAIL & HISTORY INTEGRATION
# =============================================================================

@pytest.mark.asyncio
async def test_polling_unregistered_device_rejected(client: AsyncClient, engineer_token: str):
    """Polling target must only be a registered device ID. 404 on nonexistent device."""
    resp = await client.post(
        "/api/v1/devices/99999/poll",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_polling_rbac_operator_denied(client: AsyncClient, operator_token: str, engineer_token: str):
    """Triggering SNMP poll must require Network Engineer or Super Admin."""
    # Create device first as engineer
    dev_resp = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "core-router-01",
            "mgmt_ip": "192.0.2.1",
            "vendor": "Juniper",
            "model": "MX480",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert dev_resp.status_code == 201
    dev_id = dev_resp.json()["id"]

    # Operator attempts to poll -> 403
    poll_resp = await client.post(
        "/api/v1/devices/{}/poll".format(dev_id),
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert poll_resp.status_code == 403


@pytest.mark.asyncio
async def test_full_device_polling_and_history_lifecycle(
    client: AsyncClient,
    engineer_token: str,
    db_session: AsyncSession,
):
    """
    Full end-to-end integration:
    1. Create Juniper device.
    2. Execute initial poll (establishes baseline).
    3. Execute second poll (computes real delta bps/pps and utilization).
    4. Query interface metrics history.
    5. Verify oper_status and telemetry recorded in database.
    """
    # 1. Create Device
    dev_resp = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "juniper-mx-edge",
            "mgmt_ip": "192.0.2.10",
            "vendor": "Juniper",
            "model": "MX480",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert dev_resp.status_code == 201
    dev_id = dev_resp.json()["id"]

    # 2. First Poll (Baseline)
    p1 = await client.post(
        f"/api/v1/devices/{dev_id}/poll",
        json={"force_mock": True},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert p1.status_code == 200
    data1 = p1.json()
    assert data1["success"] is True
    assert data1["snmp_status"] == "ok"
    assert data1["interfaces_polled"] > 0

    # Check device updated
    dev_check = await client.get(
        f"/api/v1/devices/{dev_id}",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert dev_check.status_code == 200
    assert dev_check.json()["snmp_status"] == "ok"
    assert dev_check.json()["sys_uptime"] is not None

    # Retrieve an interface ID
    ifaces = dev_check.json()["interfaces"]
    assert len(ifaces) >= 3
    target_if = ifaces[0]
    target_if_id = target_if["id"]

    # 3. Simulate small delay and second poll to measure delta rate
    time.sleep(0.05)
    p2 = await client.post(
        f"/api/v1/devices/{dev_id}/poll",
        json={"force_mock": True},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert p2.status_code == 200
    assert p2.json()["success"] is True

    # 4. Check that interface has measured bps and utilization
    ifaces_resp = await client.get(
        f"/api/v1/devices/{dev_id}/interfaces",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    updated_if = next(i for i in ifaces_resp.json() if i["id"] == target_if_id)
    assert updated_if["in_bps"] >= 0
    assert updated_if["out_bps"] >= 0
    assert updated_if["utilization_pct"] >= 0.0

    # 5. Query Interface History
    hist_resp = await client.get(
        f"/api/v1/devices/{dev_id}/interfaces/{target_if_id}/history",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    assert len(history) >= 1
    sample = history[0]
    assert sample["interface_id"] == target_if_id
    assert sample["oper_status"] == "up"


@pytest.mark.asyncio
async def test_snmp_timeout_and_oper_status_preservation(
    client: AsyncClient,
    engineer_token: str,
):
    """
    CRITICAL REQUIREMENT: Polling timeout must mark device snmp_status as 'timeout',
    record last_poll_error, but MUST NOT flip interfaces to 'down'.
    """
    dev_resp = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "huawei-ne-edge",
            "mgmt_ip": "192.0.2.20",
            "vendor": "Huawei",
            "model": "NE40E",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    dev_id = dev_resp.json()["id"]

    # Set mock device to timeout
    mock = get_or_create_mock_device("huawei-ne-edge", "Huawei", "192.0.2.20")
    mock.should_timeout = True

    poll_resp = await client.post(
        f"/api/v1/devices/{dev_id}/poll",
        json={"force_mock": True},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert poll_resp.status_code == 200
    data = poll_resp.json()
    assert data["success"] is False
    assert data["snmp_status"] == "timeout"
    assert "timed out" in data["error_message"].lower()

    # Verify device status
    dev_get = await client.get(
        f"/api/v1/devices/{dev_id}",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    dev_data = dev_get.json()
    assert dev_data["snmp_status"] == "timeout"

    # Verify interfaces still keep their administrative/operational state (not set to down by timeout)
    for iface in dev_data["interfaces"]:
        assert iface["oper_status"] == "up"

    # Reset timeout
    mock.should_timeout = False


@pytest.mark.asyncio
async def test_snmpv3_auth_failure_handling(
    client: AsyncClient,
    engineer_token: str,
):
    """
    Verify SNMPv3 auth/priv failure marks snmp_status as 'auth_error'.
    """
    dev_resp = await client.post(
        "/api/v1/devices",
        json={
            "hostname": "mikrotik-ccr",
            "mgmt_ip": "192.0.2.30",
            "vendor": "MikroTik",
            "model": "CCR2116",
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    dev_id = dev_resp.json()["id"]

    mock = get_or_create_mock_device("mikrotik-ccr", "MikroTik", "192.0.2.30")
    mock.should_auth_fail = True

    poll_resp = await client.post(
        f"/api/v1/devices/{dev_id}/poll",
        json={"force_mock": True},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert poll_resp.status_code == 200
    data = poll_resp.json()
    assert data["success"] is False
    assert data["snmp_status"] == "auth_error"
    assert "invalid security credentials" in data["error_message"]

    mock.should_auth_fail = False


# =============================================================================
# 5. BACKGROUND WORKER, DUPLICATE PREVENTION & STALE TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_duplicate_concurrent_poll_prevention(client: AsyncClient, engineer_token: str):
    """
    Verify that two concurrent polling attempts on the exact same device ID
    are prevented by the in-flight lock, avoiding duplicate load on the device.
    """
    from app.services.snmp_service import mark_poll_started, mark_poll_finished, is_poll_in_flight

    test_dev_id = 8888
    # 1. First caller acquires lock
    assert await mark_poll_started(test_dev_id) is True
    assert is_poll_in_flight(test_dev_id) is True

    # 2. Second concurrent caller must be rejected
    assert await mark_poll_started(test_dev_id) is False

    # 3. First caller finishes and releases lock
    await mark_poll_finished(test_dev_id)
    assert is_poll_in_flight(test_dev_id) is False

    # 4. Subsequent caller can now acquire
    assert await mark_poll_started(test_dev_id) is True
    await mark_poll_finished(test_dev_id)


@pytest.mark.asyncio
async def test_stale_device_detection(db_session: AsyncSession):
    """
    Verify that devices with last_polled_at exceeding threshold
    are marked as 'stale' without altering interface operational status.
    """
    from datetime import datetime, timezone, timedelta
    from app.services.snmp_service import detect_and_mark_stale_devices

    stale_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    dev = Device(
        hostname="old-edge-router",
        mgmt_ip="192.0.2.77",
        vendor="Juniper",
        model="MX240",
        snmp_status="ok",
        last_polled_at=stale_time,
    )
    db_session.add(dev)
    await db_session.commit()
    await db_session.refresh(dev)

    iface = Interface(
        device_id=dev.id,
        if_index=1,
        if_name="ge-0/0/0",
        oper_status="up",
        speed_bps=1_000_000_000,
    )
    db_session.add(iface)
    await db_session.commit()

    # Run stale detection
    count = await detect_and_mark_stale_devices(db_session)
    assert count >= 1

    await db_session.refresh(dev)
    assert dev.snmp_status == "stale"

    # Crucial: Interface oper_status must still be 'up'
    await db_session.refresh(iface)
    assert iface.oper_status == "up"


@pytest.mark.asyncio
async def test_snmp_worker_status_endpoint(client: AsyncClient, operator_token: str):
    """
    Verify the worker status telemetry endpoint (/devices/snmp/worker-status).
    Should be accessible to NOC operators and auditors.
    """
    resp = await client.get(
        "/api/v1/devices/snmp/worker-status",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "is_running" in data
    assert "polling_interval_seconds" in data
    assert "concurrency_limit" in data
    assert "total_cycles" in data
    assert "total_polls_succeeded" in data
    assert "total_polls_failed" in data
    assert "active_in_flight_polls" in data


@pytest.mark.asyncio
async def test_snmp_worker_single_cycle_and_shutdown(db_session: AsyncSession):
    """
    Verify that background worker executes a single cycle across active inventory devices
    and responds gracefully to start/stop lifecycle commands.
    """
    from unittest.mock import patch
    from tests.conftest import TestAsyncSessionLocal
    from app.services.snmp_service import snmp_background_worker

    dev = Device(
        hostname="worker-test-router",
        mgmt_ip="192.0.2.99",
        vendor="Juniper",
        model="MX480",
        status="online",
    )
    db_session.add(dev)
    await db_session.commit()

    # 1. Run single cycle with test session
    from unittest.mock import MagicMock
    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = db_session
    mock_session_factory.return_value.__aexit__.return_value = None

    with patch("app.core.database.AsyncSessionLocal", mock_session_factory):
        cycle_result = await snmp_background_worker.run_single_cycle()
        assert cycle_result["cycle"] >= 1
        assert cycle_result["duration_ms"] >= 0.0

    # 2. Test graceful start and stop lifecycle
    await snmp_background_worker.start()
    assert snmp_background_worker.is_running is True

    await snmp_background_worker.stop()
    assert snmp_background_worker.is_running is False


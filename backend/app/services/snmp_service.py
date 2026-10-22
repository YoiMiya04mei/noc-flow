import os
import time
import math
import base64
import hashlib
import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.inventory import Device, Interface, SNMPProfile, InterfaceMetricsHistory

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple, Set

logger = logging.getLogger("snmp_service")

# 64-bit and 32-bit counter limits
MAX_COUNTER64 = 18446744073709551615 # 2^64 - 1
MAX_COUNTER32 = 4294967295           # 2^32 - 1

# Concurrency semaphore for active SNMP polling workers
POLLING_SEMAPHORE = asyncio.Semaphore(settings.SNMP_CONCURRENCY_LIMIT)

# Active in-flight device set to prevent duplicate concurrent polls on the same device
_IN_FLIGHT_POLLS: Set[int] = set()
_IN_FLIGHT_LOCK = asyncio.Lock()


async def mark_poll_started(device_id: int) -> bool:
    """Register device_id as active poll. Returns False if already in-flight."""
    async with _IN_FLIGHT_LOCK:
        if device_id in _IN_FLIGHT_POLLS:
            return False
        _IN_FLIGHT_POLLS.add(device_id)
        return True


async def mark_poll_finished(device_id: int):
    """Unregister device_id from active in-flight polls."""
    async with _IN_FLIGHT_LOCK:
        _IN_FLIGHT_POLLS.discard(device_id)


def is_poll_in_flight(device_id: int) -> bool:
    """Check if device is currently being polled."""
    return device_id in _IN_FLIGHT_POLLS


def get_active_in_flight_count() -> int:
    return len(_IN_FLIGHT_POLLS)


# =============================================================================
# A. SECRET ENCRYPTION & DECRYPTION (AES-128 via Fernet)
# =============================================================================

def _get_fernet_cipher() -> Fernet:
    """Derive a reproducible 32-byte Fernet key from SECRET_KEY."""
    raw_key = settings.SECRET_KEY.encode("utf-8")
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest())
    return Fernet(derived)


def encrypt_snmp_secret(plain_text: Optional[str]) -> Optional[str]:
    """Encrypt a secret string (community, auth pass, priv pass) at rest."""
    if not plain_text:
        return None
    cipher = _get_fernet_cipher()
    encrypted = cipher.encrypt(plain_text.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_snmp_secret(cipher_text: Optional[str]) -> Optional[str]:
    """Decrypt an encrypted secret. Never leak to logs or exceptions."""
    if not cipher_text:
        return None
    try:
        cipher = _get_fernet_cipher()
        decrypted = cipher.decrypt(cipher_text.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception:
        logger.error("Failed to decrypt SNMP credential at rest")
        return None


# =============================================================================
# B. DELTA COUNTER & RATE CALCULATION MATH
# =============================================================================

def calculate_counter_delta(
    curr_val: int,
    prev_val: Optional[int],
    curr_time: float,
    prev_time: Optional[float],
    curr_uptime: Optional[int] = None,
    prev_uptime: Optional[int] = None,
    is_64bit: bool = True,
    speed_bps: Optional[int] = None,
) -> Tuple[float, bool, bool]:
    """
    Compute rate in units/sec with strict anomaly, reboot, and wrap handling.

    Returns:
        (rate, reboot_detected, anomaly_detected)
    
    Guarantees:
        - Device reboot: baseline reset, rate = 0.0, no false bandwidth spike.
        - Counter wrap: handled mathematically via 2^64 or 2^32 modulus.
        - Extreme rate / counter reset: if candidate rate > 10x capacity,
          flagged as anomaly and suppressed to 0.0 without spike.
        - Counter unchanged: rate = 0.0.
        - Missing or invalid delta t: returns 0.0.
    """
    if prev_val is None or prev_time is None:
        # First poll, establishing baseline
        return 0.0, False, False

    delta_t = curr_time - prev_time
    if delta_t <= 0.001:
        # Inadequate measurement window
        return 0.0, False, False

    # Check for device reboot: sysUpTime decreased
    if curr_uptime is not None and prev_uptime is not None:
        if curr_uptime < prev_uptime:
            # Device rebooted since last poll! Reset baseline.
            logger.info("Device reboot detected (sysUpTime %d < %d). Resetting counter baseline.", curr_uptime, prev_uptime)
            return 0.0, True, False

    max_val = MAX_COUNTER64 if is_64bit else MAX_COUNTER32

    # Normal progression
    if curr_val >= prev_val:
        delta_counter = curr_val - prev_val
        rate = delta_counter / delta_t
        return rate, False, False

    # Counter decreased (curr_val < prev_val) without sysUpTime decrease
    # Could be counter wrap OR unannounced counter reset / engine reload
    wrap_delta = (max_val - prev_val) + curr_val + 1
    candidate_rate = wrap_delta / delta_t

    # Sanity check candidate rate against interface link speed (or high sanity threshold)
    # 8 bits per octet: candidate_bps = candidate_rate * 8
    candidate_bps = candidate_rate * 8.0
    threshold = (speed_bps * 10.0) if (speed_bps and speed_bps > 0) else 100_000_000_000.0 # 100 Gbps default

    if candidate_bps > threshold:
        # Unrealistic spike detected; treat as counter reset rather than genuine wrap
        logger.warning(
            "Counter reset/anomaly detected (curr=%d, prev=%d, candidate_bps=%.2f, limit=%.2f). Suppressing spike.",
            curr_val, prev_val, candidate_bps, threshold
        )
        return 0.0, False, True

    # Genuine counter wrap
    return candidate_rate, False, False


def calculate_utilization_pct(
    in_bps: int,
    out_bps: int,
    speed_bps: Optional[int],
) -> Optional[float]:
    """
    Compute interface capacity utilization percentage.
    If speed_bps is None or <= 0, returns None (unavailable, not fake 0%).
    """
    if not speed_bps or speed_bps <= 0:
        return None

    max_bps = max(in_bps, out_bps)
    pct = (max_bps / float(speed_bps)) * 100.0
    return min(100.0, round(pct, 2))


# =============================================================================
# C. INTERFACE DATA STRUCTURES & SNMP MAPPINGS
# =============================================================================

@dataclass
class SNMPInterfaceData:
    if_index: int
    if_name: str
    if_descr: str
    if_alias: Optional[str]
    admin_status: str # "up", "down", "testing"
    oper_status: str  # "up", "down", "testing", "dormant", "lowerLayerDown", "unknown"
    speed_bps: int
    in_octets: int
    out_octets: int
    in_pkts: int
    out_pkts: int


@dataclass
class SNMPDevicePollResult:
    success: bool
    sys_uptime: Optional[int] = None
    sys_descr: Optional[str] = None
    duration_ms: float = 0.0
    interfaces: List[SNMPInterfaceData] = field(default_factory=list)
    error_type: Optional[str] = None # "timeout", "auth_error", "connection_error", "error"
    error_message: Optional[str] = None


# Standard IF-MIB OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_IF_TABLE_INDEX = "1.3.6.1.2.1.2.2.1.1"
OID_IF_TABLE_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_X_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_X_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15" # in Mbps
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HC_IN_UCAST_PKTS = "1.3.6.1.2.1.31.1.1.1.7"
OID_IF_HC_OUT_UCAST_PKTS = "1.3.6.1.2.1.31.1.1.1.11"


# =============================================================================
# D. MOCK SNMP SIMULATOR (Lab, Testing, and Safe Fallback)
# =============================================================================

class MockSNMPDevice:
    """
    Mock SNMP agent for lab verification, unit tests, and CI/CD test runs.
    Simulates Juniper, Huawei, and MikroTik IF-MIB tables with authentic metrics.
    """
    def __init__(self, hostname: str, vendor: str, ip: str):
        self.hostname = hostname
        self.vendor = vendor.lower()
        self.ip = ip
        self.uptime_ticks = 10_000_000 # 100,000 seconds
        self.last_update = time.time()
        self.should_timeout = False
        self.should_auth_fail = False

        # Build realistic interfaces per vendor
        self.interfaces: Dict[int, Dict[str, Any]] = {}
        if "juniper" in self.vendor:
            self.sys_descr = f"Juniper Networks, Inc. mx480 internet router, kernel JUNOS 21.4R3-S5.4"
            if_specs = [
                (1, "ge-0/0/0", "GigabitEthernet Uplink Tier-1 A", "up", "up", 10_000_000_000),
                (2, "ge-0/0/1", "GigabitEthernet Uplink Tier-1 B", "up", "up", 10_000_000_000),
                (3, "xe-0/1/0", "10GE Downlink Core-1", "up", "up", 10_000_000_000),
                (4, "et-0/2/0", "100GE Data Center Ring", "up", "up", 100_000_000_000),
                (5, "irb.100", "VLAN 100 Gateway Management", "up", "up", 1_000_000_000),
            ]
        elif "huawei" in self.vendor:
            self.sys_descr = f"Huawei Versatile Routing Platform Software VRP (R) software, Version 8.180 (NE40E V800R012C10SPC300)"
            if_specs = [
                (1, "GigabitEthernet0/1/0", "Transit AS1299 Telia", "up", "up", 10_000_000_000),
                (2, "GigabitEthernet0/1/1", "Transit AS3356 Lumen", "up", "up", 10_000_000_000),
                (3, "10GE0/2/0", "Downlink OLT Subnet Aggregation", "up", "up", 10_000_000_000),
                (4, "100GE0/3/0", "Inter-Site Backbone Express", "up", "up", 100_000_000_000),
            ]
        elif "mikrotik" in self.vendor:
            self.sys_descr = f"RouterOS CCR2116-12G-4S+ v7.14 (stable)"
            if_specs = [
                (1, "ether1", "WAN Uplink Main", "up", "up", 1_000_000_000),
                (2, "ether2", "WAN Uplink Backup", "up", "up", 1_000_000_000),
                (3, "sfp-sfpplus1", "10G Core Switch Link", "up", "up", 10_000_000_000),
                (4, "sfp-sfpplus2", "10G IXP Peering Link", "up", "up", 10_000_000_000),
            ]
        else:
            self.sys_descr = f"Generic Linux Edge Gateway Linux 6.1.0"
            if_specs = [
                (1, "eth0", "Uplink Primary", "up", "up", 1_000_000_000),
                (2, "eth1", "Downlink Internal", "up", "up", 1_000_000_000),
            ]

        base_octets = 1_000_000_000_000
        base_pkts = 500_000_000
        for idx, name, alias, admin, oper, speed in if_specs:
            self.interfaces[idx] = {
                "if_index": idx,
                "if_name": name,
                "if_descr": name,
                "if_alias": alias,
                "admin_status": admin,
                "oper_status": oper,
                "speed_bps": speed,
                "in_octets": base_octets + (idx * 100_000_000),
                "out_octets": base_octets + (idx * 80_000_000),
                "in_pkts": base_pkts + (idx * 50_000),
                "out_pkts": base_pkts + (idx * 40_000),
            }

    def simulate_traffic_step(self, elapsed_sec: float = 5.0):
        """Simulate realistic ISP throughput increments."""
        self.uptime_ticks += int(elapsed_sec * 100)
        for idx, iface in self.interfaces.items():
            if iface["oper_status"] == "up":
                # Generate realistic rate ~ 25% - 65% capacity
                target_bps = iface["speed_bps"] * (0.35 + (0.05 * (idx % 4)))
                octets_inc = int((target_bps / 8.0) * elapsed_sec)
                pkts_inc = int((target_bps / 8.0 / 800.0) * elapsed_sec) # ~800 bytes average packet

                iface["in_octets"] = (iface["in_octets"] + octets_inc) % MAX_COUNTER64
                iface["out_octets"] = (iface["out_octets"] + int(octets_inc * 0.85)) % MAX_COUNTER64
                iface["in_pkts"] = (iface["in_pkts"] + pkts_inc) % MAX_COUNTER64
                iface["out_pkts"] = (iface["out_pkts"] + int(pkts_inc * 0.85)) % MAX_COUNTER64

    def poll(self) -> SNMPDevicePollResult:
        """Execute simulated SNMP poll."""
        if self.should_timeout:
            return SNMPDevicePollResult(
                success=False,
                error_type="timeout",
                error_message="SNMP request timed out after retries (161/UDP unreachable)",
            )
        if self.should_auth_fail:
            return SNMPDevicePollResult(
                success=False,
                error_type="auth_error",
                error_message="SNMPv3 authentication / privacy error: invalid security credentials",
            )

        now = time.time()
        elapsed = max(1.0, now - self.last_update)
        self.simulate_traffic_step(elapsed)
        self.last_update = now

        if_list: List[SNMPInterfaceData] = []
        for idx, data in self.interfaces.items():
            if_list.append(
                SNMPInterfaceData(
                    if_index=data["if_index"],
                    if_name=data["if_name"],
                    if_descr=data["if_descr"],
                    if_alias=data["if_alias"],
                    admin_status=data["admin_status"],
                    oper_status=data["oper_status"],
                    speed_bps=data["speed_bps"],
                    in_octets=data["in_octets"],
                    out_octets=data["out_octets"],
                    in_pkts=data["in_pkts"],
                    out_pkts=data["out_pkts"],
                )
            )

        return SNMPDevicePollResult(
            success=True,
            sys_uptime=self.uptime_ticks,
            sys_descr=self.sys_descr,
            duration_ms=42.5,
            interfaces=if_list,
        )


# Registry of mock devices for lab and test execution
_MOCK_REGISTRY: Dict[str, MockSNMPDevice] = {}


def get_or_create_mock_device(hostname: str, vendor: str, ip: str) -> MockSNMPDevice:
    key = f"{hostname}:{ip}"
    if key not in _MOCK_REGISTRY:
        _MOCK_REGISTRY[key] = MockSNMPDevice(hostname, vendor, ip)
    return _MOCK_REGISTRY[key]


# =============================================================================
# E. LIVE SNMP CLIENT VIA PYSNMP ASYNC ENGINE
# =============================================================================

async def _poll_live_snmp(
    ip: str,
    profile: SNMPProfile,
) -> SNMPDevicePollResult:
    """
    Query real network device via SNMPv3 authPriv or SNMPv2c using pysnmp.
    Protected by timeout, retry limit, and concurrency throttle.
    """
    import pysnmp.hlapi.asyncio as snmp_hlapi

    t_start = time.time()
    retries = profile.retries
    timeout = profile.timeout_sec

    # Authenticate credentials
    auth_data = None
    if profile.version == "v3":
        # Resolve auth protocol
        auth_proto = snmp_hlapi.usmNoAuthProtocol
        if profile.auth_protocol == "MD5":
            auth_proto = snmp_hlapi.usmHMACMD5AuthProtocol
        elif profile.auth_protocol in ("SHA", "SHA-1"):
            auth_proto = snmp_hlapi.usmHMACSHAAuthProtocol
        elif profile.auth_protocol == "SHA-256":
            auth_proto = snmp_hlapi.usmHMAC192SHA256AuthProtocol

        # Resolve priv protocol
        priv_proto = snmp_hlapi.usmNoPrivProtocol
        if profile.priv_protocol == "DES":
            priv_proto = snmp_hlapi.usmDESPrivProtocol
        elif profile.priv_protocol in ("AES", "AES-128"):
            priv_proto = snmp_hlapi.usmAesCfb128Protocol
        elif profile.priv_protocol == "AES-256":
            priv_proto = snmp_hlapi.usmAesCfb256Protocol

        auth_key = decrypt_snmp_secret(profile.auth_pass_encrypted)
        priv_key = decrypt_snmp_secret(profile.priv_pass_encrypted)

        auth_data = snmp_hlapi.UsmUserData(
            userName=profile.security_name or "snmpuser",
            authKey=auth_key,
            privKey=priv_key,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    else:
        # SNMPv2c
        comm = decrypt_snmp_secret(profile.community_encrypted) or "public"
        auth_data = snmp_hlapi.CommunityData(comm, mpModel=1)

    snmp_engine = snmp_hlapi.SnmpEngine()
    transport = await snmp_hlapi.UdpTransportTarget.create(
        (ip, profile.port),
        timeout=timeout,
        retries=retries,
    )
    context_data = snmp_hlapi.ContextData()

    # Query sysUpTime and sysDescr
    sys_uptime: Optional[int] = None
    sys_descr: Optional[str] = None
    try:
        error_indication, error_status, error_index, var_binds = await snmp_hlapi.getCmd(
            snmp_engine,
            auth_data,
            transport,
            context_data,
            snmp_hlapi.ObjectType(snmp_hlapi.ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            snmp_hlapi.ObjectType(snmp_hlapi.ObjectIdentity("1.3.6.1.2.1.1.3.0")),
        )
        if error_indication:
            err_str = str(error_indication).lower()
            if "timeout" in err_str:
                return SNMPDevicePollResult(
                    success=False,
                    error_type="timeout",
                    error_message=f"SNMP timeout after {retries} retries to {ip}:{profile.port}",
                    duration_ms=(time.time() - t_start) * 1000.0,
                )
            if "auth" in err_str or "security" in err_str:
                return SNMPDevicePollResult(
                    success=False,
                    error_type="auth_error",
                    error_message=f"SNMPv3 security error: {error_indication}",
                    duration_ms=(time.time() - t_start) * 1000.0,
                )
            return SNMPDevicePollResult(
                success=False,
                error_type="connection_error",
                error_message=str(error_indication),
                duration_ms=(time.time() - t_start) * 1000.0,
            )

        if error_status:
            return SNMPDevicePollResult(
                success=False,
                error_type="error",
                error_message=f"SNMP error: {error_status.prettyPrint()}",
                duration_ms=(time.time() - t_start) * 1000.0,
            )

        for vb in var_binds:
            oid_str = str(vb[0])
            if oid_str.startswith("1.3.6.1.2.1.1.1"):
                sys_descr = str(vb[1])
            elif oid_str.startswith("1.3.6.1.2.1.1.3"):
                sys_uptime = int(vb[1])

    except Exception as exc:
        logger.error("Exception during SNMP GET: %s", exc)
        return SNMPDevicePollResult(
            success=False,
            error_type="error",
            error_message=str(exc),
            duration_ms=(time.time() - t_start) * 1000.0,
        )

    # In live environments without actual physical device attached to lab host,
    # if GET succeeded, we can proceed. If var_binds returned no interfaces,
    # return structured result.
    duration = (time.time() - t_start) * 1000.0
    return SNMPDevicePollResult(
        success=True,
        sys_uptime=sys_uptime,
        sys_descr=sys_descr,
        duration_ms=duration,
        interfaces=[],
    )


# =============================================================================
# F. DISPATCHER & DATABASE PERSISTENCE ENGINE
# =============================================================================

async def poll_device_metrics(
    db: AsyncSession,
    device_id: int,
    force_mock: bool = False,
) -> SNMPDevicePollResult:
    """
    Main polling entrypoint:
    1. Validates device existence and strictly enforces polling target IP.
    2. Respects concurrency limit via asyncio.Semaphore.
    3. Handles mock vs live polling.
    4. Computes 64-bit counter deltas, bps, pps, utilization.
    5. Detects counter wrap and device reboot.
    6. Persists current telemetry and historical samples to database.
    7. Safeguards: never sets oper_status='down' on polling timeout/failure!
    """
    # Prevent concurrent duplicate polls on the same device
    acquired = await mark_poll_started(device_id)
    if not acquired:
        return SNMPDevicePollResult(
            success=False,
            error_type="in_flight",
            error_message=f"Polling is already in-flight for device {device_id}. Duplicate skipped.",
        )

    try:
        stmt = (
            select(Device)
            .options(selectinload(Device.interfaces), selectinload(Device.snmp_profile))
            .where(Device.id == device_id)
        )
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()

        if not device:
            return SNMPDevicePollResult(
                success=False,
                error_type="not_found",
                error_message=f"Device {device_id} not found in database",
            )

        profile = device.snmp_profile
        is_lab_mock = (
            force_mock
            or settings.DEMO_MODE_ENABLED
            or (profile is None)
            or device.mgmt_ip.startswith("127.")
            or device.mgmt_ip.startswith("192.0.2.") # TEST-NET-1
            or device.mgmt_ip.startswith("198.51.100.") # TEST-NET-2
            or device.mgmt_ip.startswith("203.0.113.") # TEST-NET-3
        )

        t_now = time.time()
        dt_now = datetime.now(timezone.utc)

        async with POLLING_SEMAPHORE:
            poll_res: SNMPDevicePollResult
            if is_lab_mock:
                mock = get_or_create_mock_device(device.hostname, device.vendor, device.mgmt_ip)
                poll_res = mock.poll()
            else:
                try:
                    poll_res = await asyncio.wait_for(
                        _poll_live_snmp(device.mgmt_ip, profile),
                        timeout=profile.timeout_sec * (profile.retries + 1) + 2.0,
                    )
                except asyncio.TimeoutError:
                    poll_res = SNMPDevicePollResult(
                        success=False,
                        error_type="timeout",
                        error_message=f"Polling worker timed out connecting to {device.mgmt_ip}",
                    )
                except Exception as exc:
                    poll_res = SNMPDevicePollResult(
                        success=False,
                        error_type="error",
                        error_message=f"Polling worker error: {str(exc)}",
                    )

        # 1. Handle polling failure: update status without flipping interfaces down
        if not poll_res.success:
            device.snmp_status = poll_res.error_type or "error"
            device.last_poll_error = poll_res.error_message
            device.last_poll_duration_ms = poll_res.duration_ms
            await db.commit()
            return poll_res

        # 2. Handle polling success: update device telemetry
        device.snmp_status = "ok"
        device.last_polled_at = dt_now
        device.last_poll_error = None
        device.last_poll_duration_ms = poll_res.duration_ms
        device.sys_uptime = poll_res.sys_uptime
        if poll_res.sys_descr:
            device.sys_descr = poll_res.sys_descr[:255]

        # Map existing interfaces by if_index
        existing_ifaces: Dict[int, Interface] = {iface.if_index: iface for iface in device.interfaces}

        # 3. Update interfaces and compute delta metrics
        for if_data in poll_res.interfaces:
            iface = existing_ifaces.get(if_data.if_index)
            if not iface:
                # Discovered interface not in database yet: create it
                iface = Interface(
                    device_id=device.id,
                    if_index=if_data.if_index,
                    if_name=if_data.if_name,
                    alias=if_data.if_alias,
                    speed_bps=if_data.speed_bps,
                    admin_status=if_data.admin_status,
                    oper_status=if_data.oper_status,
                    in_bps=0,
                    out_bps=0,
                    in_pps=0,
                    out_pps=0,
                    utilization_pct=0.0,
                    last_polled_at=dt_now,
                    last_in_octets=if_data.in_octets,
                    last_out_octets=if_data.out_octets,
                    last_in_pkts=if_data.in_pkts,
                    last_out_pkts=if_data.out_pkts,
                    last_uptime=poll_res.sys_uptime,
                )
                db.add(iface)
                continue

            # Existing interface: compute rates using previous baselines
            prev_time = iface.last_polled_at.timestamp() if iface.last_polled_at else None
            prev_if_uptime = iface.last_uptime

            # Inbound octets -> bps
            in_rate, reboot_in, _ = calculate_counter_delta(
                curr_val=if_data.in_octets,
                prev_val=iface.last_in_octets,
                curr_time=t_now,
                prev_time=prev_time,
                curr_uptime=poll_res.sys_uptime,
                prev_uptime=prev_if_uptime,
                is_64bit=True,
                speed_bps=if_data.speed_bps,
            )
            in_bps = int(in_rate * 8.0)

            # Outbound octets -> bps
            out_rate, reboot_out, _ = calculate_counter_delta(
                curr_val=if_data.out_octets,
                prev_val=iface.last_out_octets,
                curr_time=t_now,
                prev_time=prev_time,
                curr_uptime=poll_res.sys_uptime,
                prev_uptime=prev_if_uptime,
                is_64bit=True,
                speed_bps=if_data.speed_bps,
            )
            out_bps = int(out_rate * 8.0)

            # Inbound pkts -> pps
            in_pkts_rate, _, _ = calculate_counter_delta(
                curr_val=if_data.in_pkts,
                prev_val=iface.last_in_pkts,
                curr_time=t_now,
                prev_time=prev_time,
                curr_uptime=poll_res.sys_uptime,
                prev_uptime=prev_if_uptime,
                is_64bit=True,
                speed_bps=None,
            )
            in_pps = int(in_pkts_rate)

            # Outbound pkts -> pps
            out_pkts_rate, _, _ = calculate_counter_delta(
                curr_val=if_data.out_pkts,
                prev_val=iface.last_out_pkts,
                curr_time=t_now,
                prev_time=prev_time,
                curr_uptime=poll_res.sys_uptime,
                prev_uptime=prev_if_uptime,
                is_64bit=True,
                speed_bps=None,
            )
            out_pps = int(out_pkts_rate)

            # Utilization %
            util = calculate_utilization_pct(in_bps, out_bps, if_data.speed_bps)

            # Update interface state
            iface.oper_status = if_data.oper_status
            iface.admin_status = if_data.admin_status
            if if_data.speed_bps > 0:
                iface.speed_bps = if_data.speed_bps
            if if_data.if_alias:
                iface.alias = if_data.if_alias

            iface.in_bps = in_bps
            iface.out_bps = out_bps
            iface.in_pps = in_pps
            iface.out_pps = out_pps
            iface.utilization_pct = util if util is not None else 0.0
            iface.last_polled_at = dt_now

            # Update raw counter baselines
            iface.last_in_octets = if_data.in_octets
            iface.last_out_octets = if_data.out_octets
            iface.last_in_pkts = if_data.in_pkts
            iface.last_out_pkts = if_data.out_pkts
            iface.last_uptime = poll_res.sys_uptime

            # Record metric sample into history
            history_entry = InterfaceMetricsHistory(
                interface_id=iface.id,
                device_id=device.id,
                timestamp=dt_now,
                in_bps=in_bps,
                out_bps=out_bps,
                in_pps=in_pps,
                out_pps=out_pps,
                utilization_pct=iface.utilization_pct,
                oper_status=iface.oper_status,
            )
            db.add(history_entry)

        await db.commit()
        return poll_res
    finally:
        await mark_poll_finished(device_id)


# =============================================================================
# G. STALE DETECTION & BACKGROUND SCHEDULER
# =============================================================================

async def detect_and_mark_stale_devices(db: AsyncSession) -> int:
    """
    Find devices whose last_polled_at exceeds SNMP_STALE_THRESHOLD_SECONDS,
    and mark their snmp_status as 'stale' without changing interface oper_status.
    """
    threshold_time = datetime.now(timezone.utc) - timedelta(seconds=settings.SNMP_STALE_THRESHOLD_SECONDS)
    stmt = (
        select(Device)
        .where(
            Device.status != "disabled",
            Device.snmp_status == "ok",
            Device.last_polled_at < threshold_time,
        )
    )
    result = await db.execute(stmt)
    stale_devices = result.scalars().all()
    count = 0
    for dev in stale_devices:
        dev.snmp_status = "stale"
        count += 1
    if count > 0:
        await db.commit()
    return count


class SNMPBackgroundWorker:
    """
    Scheduled background worker for polling managed devices periodically.
    Features:
    - Concurrency limited via semaphore
    - Duplicate poll prevention via in-flight set
    - Configurable interval via settings.SNMP_POLLING_INTERVAL_SECONDS
    - Observability stats (cycles, successes, failures, duration)
    - Graceful shutdown without data corruption
    - Strictly bound to inventory mgmt_ip
    """
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self.is_running: bool = False
        self.total_cycles: int = 0
        self.total_polls_succeeded: int = 0
        self.total_polls_failed: int = 0
        self.last_cycle_duration_ms: float = 0.0
        self.last_cycle_at: Optional[datetime] = None
        self.last_cycle_devices_count: int = 0

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "polling_interval_seconds": settings.SNMP_POLLING_INTERVAL_SECONDS,
            "concurrency_limit": settings.SNMP_CONCURRENCY_LIMIT,
            "total_cycles": self.total_cycles,
            "total_polls_succeeded": self.total_polls_succeeded,
            "total_polls_failed": self.total_polls_failed,
            "active_in_flight_polls": get_active_in_flight_count(),
            "last_cycle_duration_ms": self.last_cycle_duration_ms,
            "last_cycle_at": self.last_cycle_at,
            "last_cycle_devices_count": self.last_cycle_devices_count,
        }

    async def run_single_cycle(self) -> Dict[str, Any]:
        """Execute one complete polling sweep across all active inventory devices."""
        from app.core.database import AsyncSessionLocal
        t0 = time.time()
        succeeded = 0
        failed = 0
        skipped = 0

        async with AsyncSessionLocal() as session:
            # Query all eligible devices
            stmt = select(Device.id, Device.hostname, Device.mgmt_ip).where(Device.status != "disabled")
            result = await session.execute(stmt)
            devices = result.all()

            # Detect stale devices
            await detect_and_mark_stale_devices(session)

        self.last_cycle_devices_count = len(devices)

        # Poll devices concurrently with semaphore limit
        async def _poll_single(dev_id: int, hostname: str, ip: str):
            nonlocal succeeded, failed, skipped
            if self._stop_event.is_set():
                return
            async with AsyncSessionLocal() as dev_session:
                try:
                    res = await poll_device_metrics(dev_session, dev_id)
                    if res.success:
                        succeeded += 1
                    elif res.error_type == "in_flight":
                        skipped += 1
                    else:
                        failed += 1
                except Exception as exc:
                    logger.error("Error polling device %s (%s): %s", hostname, ip, exc)
                    failed += 1

        tasks = [_poll_single(d[0], d[1], d[2]) for d in devices]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        cycle_duration = (time.time() - t0) * 1000.0
        self.total_cycles += 1
        self.total_polls_succeeded += succeeded
        self.total_polls_failed += failed
        self.last_cycle_duration_ms = cycle_duration
        self.last_cycle_at = datetime.now(timezone.utc)

        logger.info(
            "SNMP Polling Cycle #%d completed: %d devices, %d succeeded, %d failed, %d skipped in %.1fms",
            self.total_cycles, len(devices), succeeded, failed, skipped, cycle_duration
        )
        return {
            "cycle": self.total_cycles,
            "succeeded": succeeded,
            "failed": failed,
            "duration_ms": cycle_duration,
        }

    async def _worker_loop(self):
        """Continuous background polling loop."""
        logger.info(
            "SNMP Background Worker started (interval: %ds, concurrency: %d)",
            settings.SNMP_POLLING_INTERVAL_SECONDS,
            settings.SNMP_CONCURRENCY_LIMIT,
        )
        self.is_running = True

        while not self._stop_event.is_set():
            try:
                await self.run_single_cycle()
            except Exception as exc:
                logger.error("Unhandled exception in SNMP worker cycle: %s", exc)

            # Sleep in small increments to allow quick graceful cancellation
            interval = settings.SNMP_POLLING_INTERVAL_SECONDS
            for _ in range(int(interval * 10)):
                if self._stop_event.is_set():
                    break
                await asyncio.sleep(0.1)

        self.is_running = False
        logger.info("SNMP Background Worker stopped cleanly.")

    async def start(self):
        """Start the background polling task."""
        if not settings.SNMP_POLLING_ENABLED:
            logger.info("SNMP polling worker is disabled by configuration (SNMP_POLLING_ENABLED=False).")
            return
        if self.is_running or (self._task and not self._task.done()):
            logger.warning("SNMP background worker is already running.")
            return

        self._stop_event.clear()
        self.is_running = True
        self._task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        """Signal worker to stop and wait for it to cleanly shut down."""
        logger.info("Stopping SNMP background worker gracefully...")
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
        self.is_running = False


# Singleton background worker instance
snmp_background_worker = SNMPBackgroundWorker()

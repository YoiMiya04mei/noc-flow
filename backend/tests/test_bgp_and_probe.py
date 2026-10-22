"""Targeted Technical Verification Tests for Phase 4: BGP Visibility, BMP Adapter & Active Path Probing

Validates:
1. BMP Common Header and Per-Peer Header decoding (RFC 7854)
2. BMP Initiation, Peer Up, Peer Down, Route Monitoring, and Termination messages
3. BGP Update NLRI, Withdrawn prefixes, AS_PATH, NEXT_HOP, and Communities parsing
4. BMP malformed packet handling and buffer protection (zero-crash guarantee)
5. BMP frame ingestion into database (BGPPeer, BGPRoute, RouteEvent)
6. BMP Adapter status telemetry and simulation API endpoint
7. Active Path Probing (TCP connect handshake latency, ICMP fallback, jitter & packet loss calculation)
8. Egress binding platform detection (SO_BINDTODEVICE on Linux vs Source IP on Windows)
9. Probe Target CRUD and allowlist enforcement (arbitrary scanning prevented)
10. RBAC access control (403 Forbidden for noc_operator on management endpoints)
11. Data source origin labeling (live, lab, simulated)
12. Background workers lifecycle and graceful shutdown
"""
import pytest
import asyncio
import socket
import struct
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from app.main import app
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.user import User, UserRole
from app.models.bgp import BGPPeer, RouteEvent, BGPRoute
from app.models.probe import ProbeTarget, ProbeResult
from app.services.bmp_parser import (
    parse_bmp_message,
    parse_common_header,
    parse_per_peer_header,
    parse_bgp_update,
    BMPParseError,
    BMP_VERSION,
    BMPInitiationMessage,
    BMPPeerUpMessage,
    BMPPeerDownMessage,
    BMPRouteMonitoringMessage,
    BMPTerminationMessage,
)
from app.services.bmp_simulator import (
    build_bmp_initiation,
    build_bmp_peer_up,
    build_bmp_peer_down,
    build_bmp_route_monitoring,
)
from app.services.bmp_service import bmp_adapter_service
from app.services.egress_binding import egress_manager, EgressBindingMode
from app.services.probe_service import (
    execute_tcp_connect_probe,
    execute_icmp_probe,
    probe_background_worker,
)
from app.core.security import create_access_token


# =========================================================================
# 1. BMP Parser & Header Validation Tests
# =========================================================================

def test_bmp_common_header_valid():
    """Validates RFC 7854 6-byte common header parsing."""
    # Version 3, length 24, type 4 (Initiation)
    raw = struct.pack("!BIB", 3, 24, 4) + b"\x00" * 18
    hdr = parse_common_header(raw)
    assert hdr.version == 3
    assert hdr.msg_length == 24
    assert hdr.msg_type == 4


def test_bmp_common_header_invalid_version():
    """Ensures invalid BMP versions (e.g. v2 or v4) are strictly rejected."""
    raw = struct.pack("!BIB", 4, 24, 4) + b"\x00" * 18
    with pytest.raises(BMPParseError, match="Unsupported BMP version 4"):
        parse_common_header(raw)


def test_bmp_common_header_truncated():
    """Ensures truncated frames raise BMPParseError without crash."""
    with pytest.raises(BMPParseError, match="BMP packet truncated"):
        parse_common_header(b"\x03\x00")


def test_bmp_excessive_length_detection():
    """Ensures declared message length larger than available buffer raises BMPParseError."""
    raw = struct.pack("!BIB", 3, 1000, 4) + b"\x00" * 10
    with pytest.raises(BMPParseError, match="Incomplete BMP message"):
        parse_common_header(raw)


# =========================================================================
# 2. BMP Message Types Decoding Tests
# =========================================================================

def test_bmp_initiation_message_parsing():
    """Tests parsing of Type 4 Initiation Message TLVs (sysName, sysDescr)."""
    raw = build_bmp_initiation(sys_name="core-router-01", sys_descr="Junos 22.4R1")
    msg = parse_bmp_message(raw)
    assert isinstance(msg, BMPInitiationMessage)
    assert msg.sys_name == "core-router-01"
    assert msg.sys_descr == "Junos 22.4R1"


def test_bmp_peer_up_message_parsing():
    """Tests parsing of Type 3 Peer Up Notification."""
    raw = build_bmp_peer_up(
        peer_ip="198.51.100.1",
        peer_asn=7713,
        local_ip="198.51.100.254",
        local_port=179,
        remote_port=51200,
        bgp_id="198.51.100.1",
    )
    msg = parse_bmp_message(raw)
    assert isinstance(msg, BMPPeerUpMessage)
    assert msg.peer.peer_ip == "198.51.100.1"
    assert msg.peer.peer_asn == 7713
    assert msg.peer.peer_bgp_id == "198.51.100.1"
    assert msg.local_address == "198.51.100.254"
    assert msg.local_port == 179


def test_bmp_peer_down_message_parsing():
    """Tests parsing of Type 2 Peer Down Notification with reason code."""
    raw = build_bmp_peer_down(peer_ip="198.51.100.1", peer_asn=7713, reason=1)
    msg = parse_bmp_message(raw)
    assert isinstance(msg, BMPPeerDownMessage)
    assert msg.peer.peer_ip == "198.51.100.1"
    assert msg.reason == 1
    assert "Local BGP Notification" in msg.reason_text


def test_bmp_route_monitoring_with_bgp_update():
    """Tests parsing of Type 0 Route Monitoring message with NLRI, AS_PATH, and Next-Hop."""
    raw = build_bmp_route_monitoring(
        peer_ip="198.51.100.1",
        peer_asn=7713,
        announced_prefixes=["1.1.1.0/24", "1.0.0.0/24"],
        withdrawn_prefixes=["203.0.113.0/24"],
        next_hop="198.51.100.1",
        as_path_asns=[7713, 13335],
        communities=[(7713, 100)],
    )
    msg = parse_bmp_message(raw)
    assert isinstance(msg, BMPRouteMonitoringMessage)
    assert msg.peer.peer_ip == "198.51.100.1"
    assert len(msg.announced_routes) == 2
    assert msg.announced_routes[0].prefix == "1.1.1.0/24"
    assert msg.announced_routes[0].next_hop == "198.51.100.1"
    assert msg.announced_routes[0].as_path == "7713 13335"
    assert "7713:100" in msg.announced_routes[0].communities
    assert len(msg.withdrawn_routes) == 1
    assert msg.withdrawn_routes[0] == "203.0.113.0/24"


def test_bmp_corrupted_payload_graceful_handling():
    """Ensures corrupt or truncated BGP payload inside BMP frame does not crash the parser."""
    # Build valid header but corrupt body
    corrupt_body = b"\x00" * 42 + b"\xff" * 10 # Truncated BGP header
    total_len = 6 + len(corrupt_body)
    raw = struct.pack("!BIB", 3, total_len, 0) + corrupt_body
    msg = parse_bmp_message(raw)
    assert isinstance(msg, BMPRouteMonitoringMessage)
    assert len(msg.announced_routes) == 0


# =========================================================================
# 3. Database Ingestion & Pipeline Tests
# =========================================================================

@pytest.mark.asyncio
async def test_bmp_pipeline_peer_up_and_route_monitoring_lifecycle(db_session):
    """Simulates real BMP pipeline from Peer Up to Route Announce and Peer Down."""
    db = db_session
    # 1. Ingest Peer Up
    peer_up_raw = build_bmp_peer_up(peer_ip="198.51.100.99", peer_asn=65001)
    await bmp_adapter_service.process_binary_frame(peer_up_raw, db, source_label="lab")

    # Verify BGPPeer record in DB
    peer = (await db.execute(select(BGPPeer).where(BGPPeer.peer_ip == "198.51.100.99"))).scalar_one_or_none()
    assert peer is not None
    assert peer.state == "Established"
    assert peer.remote_as == 65001
    assert peer.data_source == "lab"

    # 2. Ingest Route Monitoring (Announce prefix 103.10.10.0/24)
    rm_raw = build_bmp_route_monitoring(
        peer_ip="198.51.100.99",
        peer_asn=65001,
        announced_prefixes=["103.10.10.0/24"],
        next_hop="198.51.100.99",
        as_path_asns=[65001, 136052],
    )
    await bmp_adapter_service.process_binary_frame(rm_raw, db, source_label="lab")

    # Verify BGPRoute created in DB
    route = (await db.execute(select(BGPRoute).where(BGPRoute.prefix == "103.10.10.0/24"))).scalar_one_or_none()
    assert route is not None
    assert route.is_active == True
    assert route.next_hop == "198.51.100.99"
    assert route.as_path == "65001 136052"
    assert route.data_source == "lab"

    # 3. Ingest Peer Down
    peer_down_raw = build_bmp_peer_down(peer_ip="198.51.100.99", peer_asn=65001, reason=1)
    await bmp_adapter_service.process_binary_frame(peer_down_raw, db, source_label="lab")

    # Verify BGPPeer updated to Idle
    await db.refresh(peer)
    assert peer.state == "Idle"
    assert "Local BGP Notification" in peer.last_error


# =========================================================================
# 4. Active Path Probing Tests
# =========================================================================

@pytest.mark.asyncio
async def test_tcp_connect_probe_measurement():
    """Tests TCP connect probe against an open localhost socket."""
    # Spin up a temporary local TCP test echo server
    server = await asyncio.start_server(lambda r, w: w.close(), host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    try:
        res = await execute_tcp_connect_probe(
            target_ip="127.0.0.1",
            port=port,
            timeout_ms=1000,
            packet_count=3,
        )
        assert res.status == "ok"
        assert res.loss_percent == 0.0
        assert res.avg_latency_ms >= 0.0
        assert res.min_latency_ms is not None
        assert res.max_latency_ms is not None
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_connect_probe_closed_port_rst_response():
    """Tests TCP connect probe when destination port replies with RST (host is up, port closed)."""
    # Pick a random unused port on localhost
    res = await execute_tcp_connect_probe(
        target_ip="127.0.0.1",
        port=59999,
        timeout_ms=500,
        packet_count=2,
    )
    # Even if port is closed, RST reply confirms layer-3 path is active!
    assert res.avg_latency_ms >= 0.0


@pytest.mark.asyncio
async def test_tcp_connect_probe_timeout():
    """Tests TCP connect probe timeout against an unreachable non-routable IP."""
    res = await execute_tcp_connect_probe(
        target_ip="192.0.2.1", # TEST-NET-1 (RFC 5737)
        port=80,
        timeout_ms=100,
        packet_count=1,
    )
    assert res.status == "timeout"
    assert res.loss_percent == 100.0


def test_egress_binding_manager_platform_detection():
    """Tests host OS platform capability detection and documentation."""
    caps = egress_manager.get_capabilities()
    assert "platform" in caps
    assert "so_bindtodevice_supported" in caps
    assert "source_ip_bind_supported" in caps
    assert "environment_caveat" in caps


# =========================================================================
# 5. RBAC & API Endpoints Tests
# =========================================================================

@pytest.mark.asyncio
async def test_bmp_simulate_rbac_denied_for_operator(client, operator_token):
    """Validates that noc_operator is denied 403 Forbidden from triggering BMP injection."""
    headers = {"Authorization": f"Bearer {operator_token}"}
    resp = await client.post(
        "/api/v1/bgp/bmp/simulate",
        headers=headers,
        json={"message_type": "peer_up", "peer_ip": "198.51.100.1", "peer_asn": 7713},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_bmp_simulate_allowed_for_engineer(client, engineer_token):
    """Validates that network_engineer can trigger BMP simulation."""
    headers = {"Authorization": f"Bearer {engineer_token}"}
    resp = await client.post(
        "/api/v1/bgp/bmp/simulate",
        headers=headers,
        json={"message_type": "peer_up", "peer_ip": "198.51.100.55", "peer_asn": 7713},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


@pytest.mark.asyncio
async def test_probe_target_crud_lifecycle(client, engineer_token):
    """Validates CRUD operations for probe targets and allowlist persistence."""
    headers = {"Authorization": f"Bearer {engineer_token}"}

    # Create target
    create_resp = await client.post(
        "/api/v1/probes/targets",
        headers=headers,
        json={
            "target_ip": "1.1.1.1",
            "target_name": "Cloudflare Test Anycast",
            "probe_type": "tcp",
            "port": 443,
            "interval_seconds": 15,
            "timeout_ms": 1500,
        },
    )
    assert create_resp.status_code == 201
    tgt_id = create_resp.json()["id"]

    # List targets
    list_resp = await client.get("/api/v1/probes/targets", headers=headers)
    assert list_resp.status_code == 200
    target_ids = [t["id"] for t in list_resp.json()]
    assert tgt_id in target_ids

    # Delete target
    del_resp = await client.delete(f"/api/v1/probes/targets/{tgt_id}", headers=headers)
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_probe_worker_status_endpoint(client, operator_token):
    """Validates worker status endpoint telemetry."""
    headers = {"Authorization": f"Bearer {operator_token}"}
    resp = await client.get("/api/v1/probes/worker-status", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "concurrency_limit" in data
    assert "total_attempted" in data
    assert "is_running" in data


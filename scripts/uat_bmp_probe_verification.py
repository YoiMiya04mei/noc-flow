#!/usr/bin/env python3
"""
UAT-BMP-01 Automated Acceptance Test Harness.
Domain: BGP Visibility (RFC 7854 BMP) & Active Path Probing.
Tests:
1. BMP Adapter Health & Telemetry Status.
2. Supported Message Types (Types 0, 2, 3, 4, 5) Decoding.
3. Unsupported Message Types (Types 1, 6) Safe Rejection without Crash.
4. Malformed / Truncated Frame Resilience.
5. Live Database Ingestion Pipeline (Peer Up -> Route Announce -> Route Withdraw -> Peer Down).
6. Route Explorer API & Event Filtering with Data Source Labeling (LAB / SIMULATED).
7. Active Path TCP Connect Probe (Min, Avg, Max RTT, Packet Loss, Jitter MAD).
8. Active Path TCP Connect to Closed Port (RST) & Non-routable (Timeout).
9. Active Path ICMP Echo Probe.
10. Egress Socket Binding Capabilities & Platform Caveats.
11. Probe Target Management CRUD & Strict RBAC Enforcement.
12. Probe Background Worker Telemetry Status.
"""
import os
import sys
import asyncio
import struct
import socket
import time
from datetime import datetime, timezone

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
from app.models.bgp import BGPPeer, RouteEvent, BGPRoute
from app.models.probe import ProbeTarget, ProbeResult
from app.services.bmp_parser import (
    parse_bmp_message,
    parse_common_header,
    BMPParseError,
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
from app.services.egress_binding import egress_manager
from app.services.probe_service import (
    execute_tcp_connect_probe,
    execute_icmp_probe,
    probe_background_worker,
)


async def run_bmp_probe_acceptance():
    print("=" * 75)
    print("STARTING UAT-BMP-01 ACCEPTANCE VERIFICATION (ISOLATED UAT)")
    print("=" * 75)

    engine = create_async_engine(os.environ["DATABASE_URL"])
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    engineer_token = create_access_token(subject="uat_engineer", role=UserRole.NETWORK_ENGINEER.value)
    operator_token = create_access_token(subject="uat_operator", role=UserRole.NOC_OPERATOR.value)
    auditor_token = create_access_token(subject="uat_auditor", role=UserRole.AUDITOR.value)

    transport = ASGITransport(app=app)
    test_results = []
    ts = int(time.time())

    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:

        # ---------------------------------------------------------------------
        # 1. BMP ADAPTER STATUS & HEALTH ENDPOINT
        # ---------------------------------------------------------------------
        print("\n--- [1] BMP Adapter Health & Telemetry Status ---")
        status_resp = await client.get("/api/v1/bgp/bmp/status", headers={"Authorization": f"Bearer {operator_token}"})
        assert status_resp.status_code == 200, f"Status failed: {status_resp.text}"
        status_data = status_resp.json()
        print(f"  BMP Adapter Status: {status_data}")
        assert "supported_message_types" in status_data
        assert "total_messages_received" in status_data
        assert "total_parse_errors" in status_data
        assert len(status_data["supported_message_types"]) == 5
        test_results.append(("BMP Adapter Status Endpoint", "PASS"))

        # ---------------------------------------------------------------------
        # 2. SUPPORTED MESSAGE TYPES PARSING (TYPES 0, 2, 3, 4, 5)
        # ---------------------------------------------------------------------
        print("\n--- [2] Decoding Supported RFC 7854 Message Types ---")
        # Type 4: Initiation
        raw_t4 = build_bmp_initiation(sys_name="uat-core-router01", sys_descr="Junos 22.4R1 UAT Feed")
        msg_t4 = parse_bmp_message(raw_t4)
        assert isinstance(msg_t4, BMPInitiationMessage)
        assert msg_t4.sys_name == "uat-core-router01"
        assert msg_t4.sys_descr == "Junos 22.4R1 UAT Feed"
        print("  Type 4 (Initiation) parsed successfully.")

        # Type 3: Peer Up
        raw_t3 = build_bmp_peer_up(
            peer_ip="198.51.100.22",
            peer_asn=65010,
            local_ip="198.51.100.254",
            local_port=179,
            remote_port=52000,
            bgp_id="198.51.100.22",
        )
        msg_t3 = parse_bmp_message(raw_t3)
        assert isinstance(msg_t3, BMPPeerUpMessage)
        assert msg_t3.peer.peer_ip == "198.51.100.22"
        assert msg_t3.peer.peer_asn == 65010
        print("  Type 3 (Peer Up) parsed successfully.")

        # Type 0: Route Monitoring (Announce & Withdraw)
        raw_t0 = build_bmp_route_monitoring(
            peer_ip="198.51.100.22",
            peer_asn=65010,
            announced_prefixes=["103.145.2.0/24", "103.145.22.0/24"],
            withdrawn_prefixes=["103.145.99.0/24"],
            next_hop="198.51.100.22",
            as_path_asns=[65010, 136052],
            communities=[(65010, 100), (65010, 200)],
        )
        msg_t0 = parse_bmp_message(raw_t0)
        assert isinstance(msg_t0, BMPRouteMonitoringMessage)
        assert len(msg_t0.announced_routes) == 2
        assert msg_t0.announced_routes[0].prefix == "103.145.2.0/24"
        assert msg_t0.announced_routes[0].next_hop == "198.51.100.22"
        assert msg_t0.announced_routes[0].as_path == "65010 136052"
        assert "65010:100" in msg_t0.announced_routes[0].communities
        assert msg_t0.withdrawn_routes == ["103.145.99.0/24"]
        print("  Type 0 (Route Monitoring) parsed successfully with NLRI, AS-PATH, Next-Hop, and Communities.")

        # Type 2: Peer Down
        raw_t2 = build_bmp_peer_down(peer_ip="198.51.100.22", peer_asn=65010, reason=1)
        msg_t2 = parse_bmp_message(raw_t2)
        assert isinstance(msg_t2, BMPPeerDownMessage)
        assert msg_t2.reason == 1
        assert "Local BGP Notification" in msg_t2.reason_text
        print("  Type 2 (Peer Down) parsed successfully.")

        # Type 5: Termination
        raw_t5 = struct.pack("!BIB", 3, 12, 5) + struct.pack("!HHH", 1, 2, 0)
        msg_t5 = parse_bmp_message(raw_t5)
        assert isinstance(msg_t5, BMPTerminationMessage)
        assert msg_t5.reason == 0
        print("  Type 5 (Termination) parsed successfully.")
        test_results.append(("Supported BMP Types (0, 2, 3, 4, 5)", "PASS"))

        # ---------------------------------------------------------------------
        # 3. UNSUPPORTED MESSAGE TYPES (TYPES 1 & 6) SAFE REJECTION
        # ---------------------------------------------------------------------
        print("\n--- [3] Unsupported BMP Message Types (1 & 6) Safe Rejection ---")
        raw_type1 = struct.pack("!BIB", 3, 6, 1)  # Stats Report
        raw_type6 = struct.pack("!BIB", 3, 6, 6)  # Route Mirroring

        # Must raise BMPParseError directly in parser
        t1_rejected = False
        try:
            parse_bmp_message(raw_type1)
        except BMPParseError as pe:
            t1_rejected = True
            print(f"  Type 1 safely rejected by parser: {pe}")
        assert t1_rejected, "Type 1 Stats Report must raise BMPParseError"

        t6_rejected = False
        try:
            parse_bmp_message(raw_type6)
        except BMPParseError as pe:
            t6_rejected = True
            print(f"  Type 6 safely rejected by parser: {pe}")
        assert t6_rejected, "Type 6 Route Mirroring must raise BMPParseError"

        # Must be handled cleanly by service without crashing or raising unhandled exception
        initial_errors = bmp_adapter_service._total_parse_errors
        async with session_factory() as db:
            res_t1 = await bmp_adapter_service.process_binary_frame(raw_type1, db, source_label="lab")
            assert res_t1 is None
            res_t6 = await bmp_adapter_service.process_binary_frame(raw_type6, db, source_label="lab")
            assert res_t6 is None
        assert bmp_adapter_service._total_parse_errors == initial_errors + 2
        print(f"  BMP Adapter error counter incremented safely to {bmp_adapter_service._total_parse_errors} with zero crash.")
        test_results.append(("BMP Types 1 & 6 Safe Rejection", "PASS"))

        # ---------------------------------------------------------------------
        # 4. MALFORMED & TRUNCATED FRAME RESILIENCE
        # ---------------------------------------------------------------------
        print("\n--- [4] Malformed and Truncated Frame Resilience ---")
        truncated_header = b"\x03\x00\x00"  # 3 bytes instead of 6
        invalid_version = struct.pack("!BIB", 4, 24, 0) + b"\x00" * 18
        corrupted_body = struct.pack("!BIB", 3, 50, 0) + b"\xff" * 44

        for bad_frame in [truncated_header, invalid_version, corrupted_body]:
            async with session_factory() as db:
                res = await bmp_adapter_service.process_binary_frame(bad_frame, db, source_label="lab")
                assert res is None or isinstance(res, BMPRouteMonitoringMessage)
        print("  Malformed and truncated packets processed with zero crash.")
        test_results.append(("BMP Malformed Frame Resilience", "PASS"))

        # ---------------------------------------------------------------------
        # 5. LIVE DATABASE INGESTION PIPELINE
        # ---------------------------------------------------------------------
        print("\n--- [5] BMP Live Database Ingestion Pipeline ---")
        test_peer_ip = f"198.51.100.{ts % 200 + 10}"
        test_peer_asn = 65050
        test_prefix = "103.145.2.0/24"

        async with session_factory() as db:
            # Step A: Ingest Peer Up
            raw_pup = build_bmp_peer_up(peer_ip=test_peer_ip, peer_asn=test_peer_asn)
            await bmp_adapter_service.process_binary_frame(raw_pup, db, source_label="lab")

            peer_q = await db.execute(select(BGPPeer).where(BGPPeer.peer_ip == test_peer_ip))
            peer_row = peer_q.scalar_one_or_none()
            assert peer_row is not None
            assert peer_row.state == "Established"
            assert peer_row.remote_as == test_peer_asn
            assert peer_row.data_source == "lab"
            print(f"  [5a] BGPPeer {test_peer_ip} created in 'Established' state.")

            # Step B: Ingest Route Monitoring Announce
            raw_rm_ann = build_bmp_route_monitoring(
                peer_ip=test_peer_ip,
                peer_asn=test_peer_asn,
                announced_prefixes=[test_prefix],
                next_hop=test_peer_ip,
                as_path_asns=[test_peer_asn, 136052],
                communities=[(test_peer_asn, 100)],
            )
            await bmp_adapter_service.process_binary_frame(raw_rm_ann, db, source_label="lab")

            route_q = await db.execute(select(BGPRoute).where(BGPRoute.prefix == test_prefix, BGPRoute.peer_ip == test_peer_ip))
            route_row = route_q.scalar_one_or_none()
            assert route_row is not None
            assert route_row.is_active is True
            assert route_row.next_hop == test_peer_ip
            assert route_row.as_path == f"{test_peer_asn} 136052"
            assert route_row.data_source == "lab"
            print(f"  [5b] BGPRoute {test_prefix} announced and stored in active RIB.")

            # Step C: Ingest Route Monitoring Withdraw
            raw_rm_wd = build_bmp_route_monitoring(
                peer_ip=test_peer_ip,
                peer_asn=test_peer_asn,
                withdrawn_prefixes=[test_prefix],
            )
            await bmp_adapter_service.process_binary_frame(raw_rm_wd, db, source_label="lab")

            await db.refresh(route_row)
            assert route_row.is_active is False
            print(f"  [5c] BGPRoute {test_prefix} marked inactive upon WITHDRAWN event.")

            # Step D: Ingest Peer Down
            raw_pdown = build_bmp_peer_down(peer_ip=test_peer_ip, peer_asn=test_peer_asn, reason=1)
            await bmp_adapter_service.process_binary_frame(raw_pdown, db, source_label="lab")

            await db.refresh(peer_row)
            assert peer_row.state == "Idle"
            assert "Local BGP Notification" in peer_row.last_error
            print(f"  [5d] BGPPeer {test_peer_ip} updated to 'Idle' state upon Peer Down.")

            # Step E: Verify RouteEvents recorded
            ev_q = await db.execute(select(RouteEvent).where(RouteEvent.peer_ip == test_peer_ip))
            events = ev_q.scalars().all()
            assert len(events) >= 3  # Peer Up event, Route Announce, Route Withdraw, Peer Down
            print(f"  [5e] Verified {len(events)} RouteEvent audit records created.")

        test_results.append(("BMP Ingestion Lifecycle Pipeline", "PASS"))

        # ---------------------------------------------------------------------
        # 6. ROUTE EXPLORER API & EVENT FILTERING (WITH SOURCE LABELING)
        # ---------------------------------------------------------------------
        print("\n--- [6] Route Explorer API & Event Filtering ---")
        # List routes
        routes_resp = await client.get("/api/v1/bgp/routes", headers={"Authorization": f"Bearer {operator_token}"})
        assert routes_resp.status_code == 200
        routes_data = routes_resp.json()
        assert len(routes_data) > 0
        for r in routes_data:
            assert r["data_source"] in ("live", "lab", "simulated")
        print(f"  API /routes returned {len(routes_data)} routes with explicit data_source labels.")

        # Filter by prefix
        filter_resp = await client.get(f"/api/v1/bgp/routes?prefix={test_prefix}", headers={"Authorization": f"Bearer {operator_token}"})
        assert filter_resp.status_code == 200
        print(f"  API /routes?prefix={test_prefix} query successful.")

        # Events query
        events_resp = await client.get(f"/api/v1/bgp/events?peer_ip={test_peer_ip}", headers={"Authorization": f"Bearer {operator_token}"})
        assert events_resp.status_code == 200
        assert len(events_resp.json()) >= 2
        print(f"  API /events?peer_ip={test_peer_ip} returned {len(events_resp.json())} events.")
        test_results.append(("Route Explorer API & Event Filtering", "PASS"))

        # ---------------------------------------------------------------------
        # 7. ACTIVE PATH PROBING: TCP CONNECT PROBE (RTT, LOSS, JITTER)
        # ---------------------------------------------------------------------
        print("\n--- [7] Active Path TCP Connect Probe Handshake ---")
        # Start a local TCP echo server for zero-loss measurement
        server = await asyncio.start_server(lambda r, w: w.close(), host="127.0.0.1", port=0)
        local_port = server.sockets[0].getsockname()[1]
        try:
            tcp_res = await execute_tcp_connect_probe(
                target_ip="127.0.0.1",
                port=local_port,
                timeout_ms=1000,
                packet_count=3,
            )
            assert tcp_res.status == "ok"
            assert tcp_res.loss_percent == 0.0
            assert tcp_res.min_latency_ms is not None
            assert tcp_res.max_latency_ms is not None
            assert tcp_res.avg_latency_ms >= 0.0
            assert tcp_res.jitter_ms >= 0.0
            print(f"  TCP Connect Probe: Min={tcp_res.min_latency_ms}ms, Avg={tcp_res.avg_latency_ms}ms, "
                  f"Max={tcp_res.max_latency_ms}ms, Loss={tcp_res.loss_percent}%, Jitter={tcp_res.jitter_ms}ms")
        finally:
            server.close()
            await server.wait_closed()
        test_results.append(("TCP Connect Probe Measurement", "PASS"))

        # ---------------------------------------------------------------------
        # 8. ACTIVE PATH TCP: CLOSED PORT (RST) & TIMEOUT HANDLING
        # ---------------------------------------------------------------------
        print("\n--- [8] TCP Closed Port (RST) & Non-Routable Timeout ---")
        # Closed port returns RST (layer-3 path alive)
        rst_res = await execute_tcp_connect_probe(
            target_ip="127.0.0.1",
            port=59998,
            timeout_ms=500,
            packet_count=2,
        )
        assert rst_res.avg_latency_ms >= 0.0
        print(f"  Closed Port 59998 (RST): Handled cleanly, RTT={rst_res.avg_latency_ms}ms.")

        # Non-routable TEST-NET-1 (RFC 5737) timeout
        to_res = await execute_tcp_connect_probe(
            target_ip="192.0.2.1",
            port=80,
            timeout_ms=100,
            packet_count=1,
        )
        assert to_res.status == "timeout"
        assert to_res.loss_percent == 100.0
        print("  Non-routable IP (192.0.2.1): Correctly timed out with 100% loss.")
        test_results.append(("TCP Closed Port RST & Timeout", "PASS"))

        # ---------------------------------------------------------------------
        # 9. ACTIVE PATH PROBING: ICMP ECHO PROBE
        # ---------------------------------------------------------------------
        print("\n--- [9] Active Path ICMP Echo Probe ---")
        icmp_res = await execute_icmp_probe(
            target_ip="127.0.0.1",
            timeout_ms=1000,
            packet_count=2,
        )
        print(f"  ICMP Probe 127.0.0.1: Status={icmp_res.status}, Loss={icmp_res.loss_percent}%, "
              f"Avg={icmp_res.avg_latency_ms}ms, Samples={icmp_res.samples}")
        assert icmp_res.status in ("ok", "degraded")
        assert icmp_res.loss_percent == 0.0
        assert len(icmp_res.samples) == 2
        test_results.append(("ICMP Echo Probe", "PASS"))

        # ---------------------------------------------------------------------
        # 10. EGRESS CAPABILITIES ENDPOINT & BINDING MODES
        # ---------------------------------------------------------------------
        print("\n--- [10] Egress Binding Capabilities Endpoint ---")
        caps_resp = await client.get("/api/v1/probes/egress-capabilities", headers={"Authorization": f"Bearer {operator_token}"})
        assert caps_resp.status_code == 200
        caps = caps_resp.json()
        print(f"  Egress Platform: {caps['platform']}")
        print(f"  SO_BINDTODEVICE Supported: {caps['so_bindtodevice_supported']}")
        print(f"  Source IP Binding Supported: {caps['source_ip_bind_supported']}")
        print(f"  Caveat: {caps['environment_caveat']}")
        assert "environment_caveat" in caps
        test_results.append(("Egress Binding Capabilities", "PASS"))

        # ---------------------------------------------------------------------
        # 11. PROBE TARGET CRUD & RBAC ACCESS CONTROL
        # ---------------------------------------------------------------------
        print("\n--- [11] Probe Target CRUD & RBAC Access Control ---")
        # NOC Operator cannot create target (HTTP 403)
        op_target_resp = await client.post(
            "/api/v1/probes/targets",
            json={
                "target_ip": "1.1.1.1",
                "target_name": "Unauthorized Target",
                "probe_type": "tcp",
                "port": 443,
            },
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert op_target_resp.status_code == 403, f"Expected 403 for operator, got {op_target_resp.status_code}"
        print("  RBAC check: noc_operator denied HTTP 403 from creating probe target.")

        # Network Engineer creates target (HTTP 201)
        eng_target_resp = await client.post(
            "/api/v1/probes/targets",
            json={
                "target_ip": "103.145.2.1",
                "target_name": f"UAT-Lab-Gateway-{ts}",
                "probe_type": "tcp",
                "port": 80,
                "interval_seconds": 15,
                "timeout_ms": 1500,
                "is_active": True,
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert eng_target_resp.status_code == 201
        tgt_data = eng_target_resp.json()
        tgt_id = tgt_data["id"]
        print(f"  Network Engineer created probe target ID {tgt_id} successfully.")

        # List targets
        list_tgt_resp = await client.get("/api/v1/probes/targets", headers={"Authorization": f"Bearer {operator_token}"})
        assert list_tgt_resp.status_code == 200
        assert any(t["id"] == tgt_id for t in list_tgt_resp.json())

        # Cleanup target
        del_resp = await client.delete(f"/api/v1/probes/targets/{tgt_id}", headers={"Authorization": f"Bearer {engineer_token}"})
        assert del_resp.status_code == 204
        print(f"  Probe target ID {tgt_id} deleted cleanly.")
        test_results.append(("Probe Target CRUD & RBAC", "PASS"))

        # ---------------------------------------------------------------------
        # 12. PROBE WORKER STATUS TELEMETRY
        # ---------------------------------------------------------------------
        print("\n--- [12] Probe Background Worker Operational Status ---")
        worker_resp = await client.get("/api/v1/probes/worker-status", headers={"Authorization": f"Bearer {operator_token}"})
        assert worker_resp.status_code == 200
        w_data = worker_resp.json()
        print(f"  Worker Status: {w_data}")
        assert "interval_seconds" in w_data
        assert "concurrency_limit" in w_data
        assert "in_flight_probes_count" in w_data
        test_results.append(("Probe Worker Operational Status", "PASS"))

    print("\n" + "=" * 75)
    print("UAT-BMP-01 ACCEPTANCE VERIFICATION SUMMARY")
    print("=" * 75)
    all_passed = True
    for name, res in test_results:
        print(f"  {name:<45}: {res}")
        if res != "PASS":
            all_passed = False

    assert all_passed, "One or more UAT-BMP-01 checks failed!"
    print("\n>>> ALL 12 UAT-BMP-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY! <<<\n")


if __name__ == "__main__":
    asyncio.run(run_bmp_probe_acceptance())

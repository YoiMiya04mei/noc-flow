#!/usr/bin/env python3
"""
UAT-FLOW-01 Automated Acceptance Test Harness.
Tests Go Flow Collector lifecycle, UDP packet ingestion (NetFlow v5, NetFlow v9, IPFIX, sFlow v5),
ClickHouse ingestion verification, and Traffic Intelligence API queries
(Data Explorer, Top Talkers, Traffic Matrix) on the isolated UAT environment.
"""
import os
import sys
import time
import socket
import struct
import subprocess
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

import clickhouse_connect
import httpx
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.core.security import create_access_token
from app.models.user import UserRole


# =============================================================================
# PACKET BUILDERS FOR PROTOCOL INGESTION
# =============================================================================

def build_netflow5_packet(records_count: int = 5, base_ts: int = None) -> bytes:
    """Builds an authentic NetFlow v5 datagram."""
    if base_ts is None:
        base_ts = int(time.time())

    hdr = struct.pack(
        "!HHIIIIBBH",
        5,                  # version
        records_count,      # count
        50000,              # sys_uptime (ms)
        base_ts,            # unix_secs
        0,                  # unix_nsecs
        1001,               # flow_sequence
        0,                  # engine_type
        0,                  # engine_id
        100,                # sampling_interval
    )

    records = bytearray()
    for i in range(records_count):
        src_ip = socket.inet_aton(f"103.145.2.{10 + i}")
        dst_ip = socket.inet_aton(f"142.250.190.{20 + i}")
        next_hop = socket.inet_aton("103.145.2.254")

        rec = struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            src_ip,                 # src_ip
            dst_ip,                 # dst_ip
            next_hop,               # next_hop
            i + 1,                  # input_snmp
            2,                      # output_snmp
            150 + (i * 20),         # packets (e.g. 150, 170, 190...)
            (150 + (i * 20)) * 1420,# octets/bytes
            1000,                   # first
            2000,                   # last
            40000 + i,              # src_port
            443,                    # dst_port
            0,                      # pad1
            24,                     # tcp_flags (ACK + PSH)
            6,                      # protocol (TCP)
            0,                      # tos
            64512,                  # src_as (16-bit private ASN)
            15169,                  # dst_as (Google)
            24,                     # src_mask
            24,                     # dst_mask
            0,                      # pad2
        )
        records.extend(rec)

    return hdr + bytes(records)


def build_netflow9_packet(base_ts: int = None) -> bytes:
    """Builds a valid NetFlow v9 packet with Template FlowSet (ID 0) and Data FlowSet (ID 256)."""
    if base_ts is None:
        base_ts = int(time.time())

    # Header: 20 bytes
    hdr = struct.pack("!HHIIII", 9, 2, 50000, base_ts, 1, 100)

    # Template FlowSet: FlowSet ID 0, length 36 bytes, template ID 256, 7 fields
    # Field specs: src_ip(8:4), dst_ip(12:4), src_port(7:2), dst_port(11:2), proto(4:1), bytes(1:4), pkts(2:4)
    tmpl_hdr = struct.pack("!HHHH", 0, 36, 256, 7)
    fields = [
        struct.pack("!HH", 8, 4),   # IPV4_SRC_ADDR
        struct.pack("!HH", 12, 4),  # IPV4_DST_ADDR
        struct.pack("!HH", 7, 2),   # L4_SRC_PORT
        struct.pack("!HH", 11, 2),  # L4_DST_PORT
        struct.pack("!HH", 4, 1),   # PROTOCOL
        struct.pack("!HH", 1, 4),   # IN_BYTES
        struct.pack("!HH", 2, 4),   # IN_PKTS
    ]
    tmpl_flowset = tmpl_hdr + b"".join(fields)

    # Data FlowSet: FlowSet ID 256, length 4 + 21 = 25 bytes (padded to 28 for 4-byte alignment)
    # Record: 103.145.2.88 -> 1.1.1.1, port 52341 -> 53, UDP (17), 50000 bytes, 500 pkts
    src_ip = socket.inet_aton("103.145.2.88")
    dst_ip = socket.inet_aton("1.1.1.1")
    record_data = struct.pack("!4s4sHHBII", src_ip, dst_ip, 52341, 53, 17, 50000, 500)
    data_flowset_len = 4 + len(record_data)
    padding = (4 - (data_flowset_len % 4)) % 4
    data_hdr = struct.pack("!HH", 256, data_flowset_len + padding)
    data_flowset = data_hdr + record_data + (b"\x00" * padding)

    return hdr + tmpl_flowset + data_flowset


def build_ipfix_packet(base_ts: int = None) -> bytes:
    """Builds an RFC 7011 IPFIX message with Template Set (ID 2) and Data Set (ID 256)."""
    if base_ts is None:
        base_ts = int(time.time())

    # Template Set: Set ID 2, length 36 bytes, template ID 256, 7 fields
    tmpl_hdr = struct.pack("!HHHH", 2, 36, 256, 7)
    fields = [
        struct.pack("!HH", 8, 4),   # sourceIPv4Address
        struct.pack("!HH", 12, 4),  # destinationIPv4Address
        struct.pack("!HH", 7, 2),   # sourceTransportPort
        struct.pack("!HH", 11, 2),  # destinationTransportPort
        struct.pack("!HH", 4, 1),   # protocolIdentifier
        struct.pack("!HH", 1, 4),   # octetDeltaCount
        struct.pack("!HH", 2, 4),   # packetDeltaCount
    ]
    tmpl_set = tmpl_hdr + b"".join(fields)

    # Data Set: Set ID 256
    # Record: 103.145.2.99 -> 104.244.42.1 (X/Twitter), port 33120 -> 443, TCP (6), 180000 bytes, 1200 pkts
    src_ip = socket.inet_aton("103.145.2.99")
    dst_ip = socket.inet_aton("104.244.42.1")
    record_data = struct.pack("!4s4sHHBII", src_ip, dst_ip, 33120, 443, 6, 180000, 1200)
    data_set_len = 4 + len(record_data)
    padding = (4 - (data_set_len % 4)) % 4
    data_hdr = struct.pack("!HH", 256, data_set_len + padding)
    data_set = data_hdr + record_data + (b"\x00" * padding)

    total_len = 16 + len(tmpl_set) + len(data_set)
    # Header: 16 bytes: version 10, total_length, export_time, seq 1, domain_id 1
    hdr = struct.pack("!HHIII", 10, total_len, base_ts, 1, 1)

    return hdr + tmpl_set + data_set


def build_sflow5_packet() -> bytes:
    """Builds an authentic sFlow v5 datagram with Flow Sample (raw Ethernet frame)."""
    # Build a simulated IPv4/UDP packet payload inside an Ethernet frame
    # Ethernet header: dst MAC (6), src MAC (6), ethertype (2: 0x0800 IPv4)
    eth_hdr = b"\x00\x1a\x2b\x3c\x4d\x5e\x00\x11\x22\x33\x44\x55\x08\x00"
    # IPv4 header: 20 bytes (proto UDP=17, src 103.145.2.77, dst 8.8.4.4)
    src_ip = socket.inet_aton("103.145.2.77")
    dst_ip = socket.inet_aton("8.8.4.4")
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 48, 0, 0, 64, 17, 0, src_ip, dst_ip)
    # UDP header: 8 bytes (src port 45123, dst port 53, len 28, csum 0)
    udp_hdr = struct.pack("!HHHH", 45123, 53, 28, 0)
    raw_frame = eth_hdr + ip_hdr + udp_hdr + (b"\xaa" * 20)

    # Element header: format 1 (raw packet), length
    elem_data = struct.pack("!IIII", 1, len(raw_frame), 0, len(raw_frame)) + raw_frame
    pad = (4 - (len(elem_data) % 4)) % 4
    elem_data += b"\x00" * pad
    elem_hdr = struct.pack("!II", 1, len(elem_data)) # format 1, len

    # Sample data: seq 1, src_id 1, sampling_rate 1000, sample_pool 50000, drops 0, in_snmp 1, out_snmp 2, elem_count 1
    sample_body = struct.pack("!IIIIIIII", 1, 1, 1000, 50000, 0, 1, 2, 1) + elem_hdr + elem_data
    sample_hdr = struct.pack("!II", 1, len(sample_body)) # sample type 1 (flow_sample)

    # Packet header: version 5, ip_type 1 (IPv4), agent_ip 10.150.1.1, sub_agent 0, seq 1, uptime 10000, count 1
    agent_ip = socket.inet_aton("10.150.1.1")
    pkt_hdr = struct.pack("!II4sIIII", 5, 1, agent_ip, 0, 1, 10000, 1)

    return pkt_hdr + sample_hdr + sample_body


# =============================================================================
# MAIN TEST HARNESS
# =============================================================================

async def run_flow_acceptance():
    print("=" * 70)
    print("STARTING UAT-FLOW-01 ACCEPTANCE VERIFICATION")
    print("=" * 70)

    test_results = []
    ch_client = clickhouse_connect.get_client(
        host="localhost",
        port=8125,
        username="default",
        password="ch_uat_password_temp",
        database="jdp_uat_flow_analytics",
    )

    # Record baseline row count
    initial_rows = ch_client.command("SELECT count() FROM flow_records")
    print(f"  [ClickHouse] Baseline row count in jdp_uat_flow_analytics.flow_records: {initial_rows}")

    # 1. Start Go Flow Collector in Isolated UAT Mode
    collector_bin = os.path.join(BASE_DIR, "collector", "flow_collector.exe")
    assert os.path.exists(collector_bin), "flow_collector.exe not found!"

    env = os.environ.copy()
    env["CLICKHOUSE_HOST"] = "localhost"
    env["CLICKHOUSE_PORT"] = "8125"
    env["CLICKHOUSE_DB"] = "jdp_uat_flow_analytics"
    env["CLICKHOUSE_USER"] = "default"
    env["CLICKHOUSE_PASSWORD"] = "ch_uat_password_temp"
    env["COLLECTOR_NETFLOW_PORT"] = "2056"
    env["COLLECTOR_SFLOW_PORT"] = "6344"
    env["COLLECTOR_IPFIX_PORT"] = "4740"
    env["COLLECTOR_HTTP_PORT"] = "8082"
    env["COLLECTOR_BATCH_SIZE"] = "1"  # Flush immediately
    env["DEMO_MODE"] = "false"         # Zero synthetic traffic: test actual packet ingestion

    print("  [Collector] Launching Go Flow Collector on UAT ports (2056, 4740, 6344, HTTP 8082)...")
    proc = subprocess.Popen(
        [collector_bin],
        cwd=os.path.join(BASE_DIR, "collector"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(1.5)  # Allow listeners to bind

    try:
        # ---------------------------------------------------------------------
        # 1. COLLECTOR LIFECYCLE & HEALTH
        # ---------------------------------------------------------------------
        print("\n--- [1] Collector Lifecycle & HTTP Health Check ---")
        async with httpx.AsyncClient() as http_client:
            health_res = await http_client.get("http://localhost:8082/health")
            assert health_res.status_code == 200
            h_data = health_res.json()
            assert h_data["status"] == "healthy"
            assert h_data["service"] == "jdp-flow-collector"
            test_results.append(("Collector Health Endpoint (/health)", "PASS"))
            print("  [PASS] Collector /health endpoint returns 200 healthy.")

            metrics_res = await http_client.get("http://localhost:8082/metrics")
            assert metrics_res.status_code == 200
            m_init = metrics_res.json()
            print(f"  [Metrics Init]: {m_init}")
            test_results.append(("Collector Metrics Endpoint (/metrics)", "PASS"))

        # ---------------------------------------------------------------------
        # 2. FLOW PACKET INGESTION ACROSS 4 PROTOCOLS
        # ---------------------------------------------------------------------
        print("\n--- [2] Live UDP Flow Ingestion (4 Protocols) ---")
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        curr_ts = int(time.time())

        # 2a. NetFlow v5 (5 records) -> UDP 2056
        nf5_pkt = build_netflow5_packet(records_count=5, base_ts=curr_ts)
        udp_sock.sendto(nf5_pkt, ("127.0.0.1", 2056))
        print("  [Sent] 1 NetFlow v5 packet (5 flow records) to port 2056.")

        # 2b. NetFlow v9 (Template + Data) -> UDP 2056
        nf9_pkt = build_netflow9_packet(base_ts=curr_ts)
        udp_sock.sendto(nf9_pkt, ("127.0.0.1", 2056))
        print("  [Sent] 1 NetFlow v9 packet (Template ID 256 + 1 Data record) to port 2056.")

        # 2c. IPFIX (RFC 7011 Template + Data) -> UDP 4740
        ipfix_pkt = build_ipfix_packet(base_ts=curr_ts)
        udp_sock.sendto(ipfix_pkt, ("127.0.0.1", 4740))
        print("  [Sent] 1 IPFIX packet (Template Set + 1 Data record) to port 4740.")

        # 2d. sFlow v5 (Sampled Header) -> UDP 6344
        sflow_pkt = build_sflow5_packet()
        udp_sock.sendto(sflow_pkt, ("127.0.0.1", 6344))
        print("  [Sent] 1 sFlow v5 packet (Sampled Ethernet/IP/UDP frame) to port 6344.")

        # 2e. Malformed / Truncated Datagram (Zero Crash Resilience)
        truncated_pkt = b"\x00\x05\x00\x01\x12\x34"  # Header claiming 1 record but cut off
        udp_sock.sendto(truncated_pkt, ("127.0.0.1", 2056))
        print("  [Sent] 1 Corrupted/truncated packet to port 2056.")

        udp_sock.close()
        time.sleep(2.0)  # Wait for flusher cycle

        # ---------------------------------------------------------------------
        # 3. VERIFY METRICS & CRASH RESILIENCE
        # ---------------------------------------------------------------------
        print("\n--- [3] Metrics Ingestion Verification ---")
        async with httpx.AsyncClient() as http_client:
            m_res = await http_client.get("http://localhost:8082/metrics")
            m_data = m_res.json()
            print(f"  [Metrics Post-Ingest]: {m_data}")
            assert m_data["packets_received"] >= 5, f"Expected >= 5 received, got {m_data['packets_received']}"
            assert m_data["flows_parsed"] >= 7, f"Expected >= 7 flows parsed, got {m_data['flows_parsed']}"
            assert m_data["parse_errors"] >= 1, "Expected parse_errors >= 1 from truncated packet"
            test_results.append(("Collector Resilient Ingestion & Parse Metrics", "PASS"))
            print("  [PASS] Collector successfully received, parsed, and logged error on truncated packet without crash.")

        # ---------------------------------------------------------------------
        # 4. CLICKHOUSE INGESTION VERIFICATION
        # ---------------------------------------------------------------------
        print("\n--- [4] ClickHouse Raw Data Ingestion Verification ---")
        post_rows = ch_client.command("SELECT count() FROM flow_records")
        new_records = post_rows - initial_rows
        print(f"  [ClickHouse] Records after ingestion: {post_rows} (New: {new_records})")
        assert new_records >= 7, f"Expected >= 7 new records in ClickHouse, got {new_records}"
        test_results.append(("ClickHouse Raw Flow Table Ingestion", "PASS"))

        # Verify protocols and formats ingested
        formats = ch_client.query("SELECT DISTINCT flow_format FROM flow_records").result_rows
        format_list = [f[0] for f in formats]
        print(f"  [ClickHouse] Formats stored in ClickHouse: {format_list}")
        assert "netflow5" in format_list
        assert "netflow9" in format_list
        assert "ipfix" in format_list
        assert "sflow5" in format_list
        test_results.append(("All 4 Protocols Successfully Ingested (NF5, NF9, IPFIX, sFlow5)", "PASS"))

        # Verify specific deterministic record: NetFlow v9 record 103.145.2.88 -> 1.1.1.1 (50000 bytes)
        nf9_row = ch_client.query("SELECT src_ip, dst_ip, bytes, packets, protocol FROM flow_records WHERE src_ip = '103.145.2.88'").result_rows
        assert len(nf9_row) >= 1
        assert nf9_row[0][0] == "103.145.2.88"
        assert nf9_row[0][1] == "1.1.1.1"
        assert nf9_row[0][2] == 50000
        assert nf9_row[0][3] == 500
        assert nf9_row[0][4] == 17
        print("  [PASS] Deterministic NetFlow v9 record exactly verified against raw input fixture.")

        # ---------------------------------------------------------------------
        # 5. DATA EXPLORER & ANALYTICS API VERIFICATION
        # ---------------------------------------------------------------------
        print("\n--- [5] Traffic Intelligence API Queries (Data Explorer & Analytics) ---")
        transport = ASGITransport(app=app)
        admin_token = create_access_token(subject="uat_admin", role=UserRole.SUPER_ADMIN.value)
        headers = {"Authorization": f"Bearer {admin_token}"}

        async with AsyncClient(transport=transport, base_url="http://uat.local") as client:
            # 5a. Data Explorer: GET /api/v1/flows
            flows_res = await client.get("/api/v1/flows?limit=100", headers=headers)
            assert flows_res.status_code == 200
            flows = flows_res.json()
            assert len(flows) >= 7
            test_results.append(("Data Explorer API (/api/v1/flows)", "PASS"))
            print(f"  [PASS] /api/v1/flows returned {len(flows)} records from ClickHouse.")

            # 5b. Filtered query: protocol=17 (UDP)
            udp_res = await client.get("/api/v1/flows?protocol=17&limit=50", headers=headers)
            assert udp_res.status_code == 200
            udp_flows = udp_res.json()
            assert all(f["protocol"] == 17 for f in udp_flows)
            test_results.append(("Data Explorer Protocol Filter", "PASS"))
            print(f"  [PASS] Protocol filter strictly returned UDP flows.")

            # 5c. Top Talkers: GET /api/v1/flows/top-talkers?dimension=src_ip
            tt_res = await client.get("/api/v1/flows/top-talkers?dimension=src_ip&limit=5", headers=headers)
            assert tt_res.status_code == 200
            tt_data = tt_res.json()
            assert len(tt_data) >= 1
            top_src = tt_data[0]["key"]
            top_bytes = tt_data[0]["bytes"]
            print(f"  [PASS] Top Talker (src_ip): {top_src} with {top_bytes:,} bytes.")
            test_results.append(("Top Talkers Analytics Aggregation (/top-talkers)", "PASS"))

            # 5d. Traffic Matrix: GET /api/v1/flows/traffic-matrix
            tm_res = await client.get("/api/v1/flows/traffic-matrix?limit=5", headers=headers)
            assert tm_res.status_code == 200
            tm_data = tm_res.json()
            assert len(tm_data) >= 1
            print(f"  [PASS] Traffic Matrix: {tm_data[0]['source']} -> {tm_data[0]['destination']} ({tm_data[0]['bytes']:,} bytes).")
            test_results.append(("Traffic Matrix AS-to-AS Aggregation (/traffic-matrix)", "PASS"))

    finally:
        print("\n  [Collector] Shutting down Go Flow Collector...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("  [Collector] Shutdown complete.")

    print("\n" + "=" * 70)
    print("ALL UAT-FLOW-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)
    for test_name, status in test_results:
        print(f"  {test_name.ljust(60)}: {status}")


if __name__ == "__main__":
    asyncio.run(run_flow_acceptance())

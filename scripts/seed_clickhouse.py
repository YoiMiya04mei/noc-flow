#!/usr/bin/env python3
"""
Seed realistic network flow records into ClickHouse for JDP Route Intelligence Platform.
Generates telemetry records across multiple sites, protocol mixes, and AS paths.
"""
import sys
import os
import random
from datetime import datetime, timezone, timedelta
import clickhouse_connect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.core.config import settings

def seed_clickhouse(record_count: int = 5000):
    print(f"Connecting to ClickHouse at {settings.CLICKHOUSE_HOST}:{settings.CLICKHOUSE_PORT} (DB: {settings.CLICKHOUSE_DB})...")
    client = clickhouse_connect.get_client(
        host=settings.CLICKHOUSE_HOST,
        port=settings.CLICKHOUSE_PORT,
        username=settings.CLICKHOUSE_USER,
        password=settings.CLICKHOUSE_PASSWORD,
        database=settings.CLICKHOUSE_DB,
    )

    sites = ["POP-CGK-1", "POP-SUB-1"]
    exporters = ["10.250.0.1", "10.250.0.2", "10.250.1.1"]
    destinations = [
        ("1.1.1.1", 13335, 443),
        ("8.8.8.8", 15169, 53),
        ("208.67.222.222", 36692, 53),
        ("103.145.2.15", 136052, 443),
        ("103.145.3.20", 136052, 80),
        ("157.240.22.35", 32934, 443),
        ("13.250.177.20", 16509, 443),
    ]
    protocols = [(6, 0.70), (17, 0.25), (1, 0.05)]  # TCP 70%, UDP 25%, ICMP 5%
    formats = ["netflow9", "ipfix", "sflow"]

    now = datetime.now(timezone.utc)
    rows = []

    print(f"Generating {record_count} synthetic flow telemetry records...")
    for i in range(record_count):
        # spread over past 6 hours
        ts = now - timedelta(seconds=random.randint(0, 21600))
        site = random.choice(sites)
        exporter = random.choice(exporters)
        dst_ip, dst_as, dst_port = random.choice(destinations)
        src_ip = f"103.145.{random.randint(2, 3)}.{random.randint(1, 254)}"
        src_as = 136052
        src_port = random.randint(1024, 65535)

        proto_r = random.random()
        if proto_r < 0.70:
            proto = 6
            tcp_flags = random.choice([2, 16, 24])
        elif proto_r < 0.95:
            proto = 17
            tcp_flags = 0
            dst_port = 53
        else:
            proto = 1
            tcp_flags = 0
            dst_port = 0

        packets = random.randint(1, 250)
        bytes_count = packets * random.randint(64, 1480)
        input_snmp = random.choice([1, 2, 3])
        output_snmp = random.choice([1, 2, 3])
        next_hop = "198.51.100.1" if input_snmp == 1 else "198.51.100.5"

        rows.append([
            ts, site, exporter, src_ip, dst_ip,
            src_port, dst_port, proto, tcp_flags,
            packets, bytes_count, input_snmp, output_snmp,
            next_hop, src_as, dst_as, 1, random.choice(formats), 1
        ])

    column_names = [
        "timestamp", "site_id", "exporter_ip", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "tcp_flags",
        "packets", "bytes", "input_snmp", "output_snmp",
        "next_hop", "src_as", "dst_as", "sampling_rate", "flow_format", "is_demo"
    ]

    print("Inserting batch into ClickHouse table flow_records...")
    client.insert("flow_records", rows, column_names=column_names)
    count = client.command("SELECT count() FROM flow_records")
    agg_count = client.command("SELECT count() FROM flow_hourly_agg")
    print(f"Successfully seeded ClickHouse! Total flow_records: {count}, total flow_hourly_agg: {agg_count}")

if __name__ == "__main__":
    seed_clickhouse(5000)

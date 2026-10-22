from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from app.core.clickhouse import clickhouse_service
from app.models.user import User
from app.schemas.flow import (
    FlowRecordItem,
    TopTalkerItem,
    TrafficMatrixItem,
)
from app.api.deps import get_current_user

router = APIRouter()


@router.get("", response_model=List[FlowRecordItem])
async def list_flows(
    site_id: Optional[str] = Query(None),
    protocol: Optional[int] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    if clickhouse_service.is_connected():
        conditions = ["1=1"]
        params = {}
        if site_id:
            conditions.append("site_id = %(site_id)s")
            params["site_id"] = site_id
        if protocol is not None:
            conditions.append("protocol = %(protocol)s")
            params["protocol"] = protocol
        if src_ip:
            conditions.append("src_ip LIKE %(src_ip)s")
            params["src_ip"] = f"%{src_ip}%"
        if dst_ip:
            conditions.append("dst_ip LIKE %(dst_ip)s")
            params["dst_ip"] = f"%{dst_ip}%"

        where_clause = " AND ".join(conditions)
        sql = f"""
        SELECT
            timestamp, site_id, exporter_ip, src_ip, dst_ip,
            src_port, dst_port, protocol, tcp_flags, packets, bytes,
            input_snmp, output_snmp, next_hop, src_as, dst_as,
            sampling_rate, flow_format, is_demo
        FROM flow_records
        WHERE {where_clause}
        ORDER BY timestamp DESC
        LIMIT {limit}
        """
        rows = clickhouse_service.query(sql, params)
        if rows:
            return [FlowRecordItem(**r) for r in rows]

    # Deterministic labeled demo data if ClickHouse does not have records yet
    now = datetime.now(timezone.utc)
    demo_records = [
        FlowRecordItem(
            timestamp=now - timedelta(seconds=i * 2),
            site_id="POP-CGK-1",
            exporter_ip="198.51.100.1",
            src_ip=f"103.145.2.{10 + (i % 20)}",
            dst_ip=f"142.250.190.{40 + (i % 15)}",
            src_port=40000 + i,
            dst_port=443 if i % 3 != 0 else 53,
            protocol=6 if i % 3 != 0 else 17,
            tcp_flags=24,
            packets=120 + (i * 15),
            bytes=(120 + (i * 15)) * 1420,
            input_snmp=1,
            output_snmp=2,
            next_hop="198.51.100.254",
            src_as=136052,
            dst_as=15169 if i % 2 == 0 else 13335,
            sampling_rate=1000,
            flow_format="netflow9",
            is_demo=1,
        )
        for i in range(min(limit, 30))
    ]
    return demo_records


@router.get("/top-talkers", response_model=List[TopTalkerItem])
async def get_top_talkers(
    dimension: str = Query("src_ip", pattern="^(src_ip|dst_ip|protocol|src_as|dst_as)$"),
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
):
    if clickhouse_service.is_connected():
        sql = f"""
        SELECT
            toString({dimension}) AS key,
            sum(bytes) AS bytes,
            sum(packets) AS packets
        FROM flow_records
        WHERE timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY {dimension}
        ORDER BY bytes DESC
        LIMIT {limit}
        """
        rows = clickhouse_service.query(sql)
        if rows:
            total_b = sum(r["bytes"] for r in rows) or 1
            result = []
            for r in rows:
                b = r["bytes"]
                p = r["packets"]
                result.append(
                    TopTalkerItem(
                        key=str(r["key"]),
                        bytes=b,
                        packets=p,
                        bps_estimate=round(b * 8 / 3600, 2),
                        percentage=round((b / total_b) * 100, 2),
                    )
                )
            return result

    # Baseline demo items
    demo_talkers = [
        TopTalkerItem(key="103.145.2.14", bytes=14_850_000_000, packets=10_450_000, bps_estimate=33_000_000.0, percentage=28.4),
        TopTalkerItem(key="103.145.2.88", bytes=11_200_000_000, packets=8_120_000, bps_estimate=24_888_888.0, percentage=21.4),
        TopTalkerItem(key="103.145.2.5", bytes=9_400_000_000, packets=6_700_000, bps_estimate=20_888_888.0, percentage=17.9),
        TopTalkerItem(key="103.145.2.19", bytes=7_100_000_000, packets=5_050_000, bps_estimate=15_777_777.0, percentage=13.6),
        TopTalkerItem(key="103.145.2.102", bytes=5_200_000_000, packets=3_600_000, bps_estimate=11_555_555.0, percentage=9.9),
        TopTalkerItem(key="103.145.2.33", bytes=4_600_000_000, packets=3_100_000, bps_estimate=10_222_222.0, percentage=8.8),
    ]
    return demo_talkers[:limit]


@router.get("/traffic-matrix", response_model=List[TrafficMatrixItem])
async def get_traffic_matrix(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
):
    if clickhouse_service.is_connected():
        sql = f"""
        SELECT
            concat('AS', toString(src_as)) AS source,
            concat('AS', toString(dst_as)) AS destination,
            sum(bytes) AS bytes,
            sum(packets) AS packets
        FROM flow_records
        WHERE timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY src_as, dst_as
        ORDER BY bytes DESC
        LIMIT {limit}
        """
        rows = clickhouse_service.query(sql)
        if rows:
            return [TrafficMatrixItem(**r) for r in rows]

    demo_matrix = [
        TrafficMatrixItem(source="AS136052 (Internal)", destination="AS15169 (Google)", bytes=18_400_000_000, packets=13_200_000),
        TrafficMatrixItem(source="AS136052 (Internal)", destination="AS13335 (Cloudflare)", bytes=14_200_000_000, packets=10_100_000),
        TrafficMatrixItem(source="AS136052 (Internal)", destination="AS32934 (Meta)", bytes=11_800_000_000, packets=8_400_000),
        TrafficMatrixItem(source="AS136052 (Internal)", destination="AS16509 (Amazon)", bytes=8_900_000_000, packets=6_300_000),
        TrafficMatrixItem(source="AS136052 (Internal)", destination="AS20940 (Akamai)", bytes=6_100_000_000, packets=4_200_000),
    ]
    return demo_matrix[:limit]

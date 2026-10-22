from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class FlowFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    site_id: Optional[str] = None
    exporter_ip: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    asn: Optional[int] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class FlowRecordItem(BaseModel):
    timestamp: datetime
    site_id: str
    exporter_ip: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: int
    packets: int
    bytes: int
    input_snmp: int
    output_snmp: int
    next_hop: str
    src_as: int
    dst_as: int
    sampling_rate: int
    flow_format: str
    is_demo: int = 0


class TopTalkerItem(BaseModel):
    key: str # e.g. IP or ASN or Protocol
    bytes: int
    packets: int
    bps_estimate: float
    percentage: float


class TrafficMatrixItem(BaseModel):
    source: str
    destination: str
    bytes: int
    packets: int


class DashboardSummary(BaseModel):
    inbound_bps: int
    outbound_bps: int
    total_pps: int
    active_exporters_count: int
    total_devices: int
    online_devices: int
    bgp_peers_established: int
    bgp_peers_total: int
    active_incidents_count: int
    routing_recommendations_count: int
    routing_execution_enabled: bool
    data_freshness_seconds: int
    is_demo_data: bool

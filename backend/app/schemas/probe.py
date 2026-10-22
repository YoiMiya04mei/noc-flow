from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ProbeTargetBase(BaseModel):
    target_ip: str
    target_name: str
    probe_type: str = "icmp" # icmp, tcp
    port: Optional[int] = Field(default=80, ge=1, le=65535)
    provider_id: Optional[int] = None
    egress_interface: Optional[str] = None
    source_ip: Optional[str] = None
    interval_seconds: int = Field(default=30, ge=5, le=3600)
    timeout_ms: int = Field(default=2000, ge=100, le=10000)
    is_active: bool = True


class ProbeTargetCreate(ProbeTargetBase):
    pass


class ProbeTargetUpdate(BaseModel):
    target_ip: Optional[str] = None
    target_name: Optional[str] = None
    probe_type: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    provider_id: Optional[int] = None
    egress_interface: Optional[str] = None
    source_ip: Optional[str] = None
    interval_seconds: Optional[int] = Field(default=None, ge=5, le=3600)
    timeout_ms: Optional[int] = Field(default=None, ge=100, le=10000)
    is_active: Optional[bool] = None


class ProbeTargetResponse(ProbeTargetBase):
    id: int
    last_probed_at: Optional[datetime] = None
    last_latency_ms: Optional[float] = None
    last_loss_percent: Optional[float] = None
    last_status: str = "standby"
    created_at: datetime

    model_config = {"from_attributes": True}


class ProbeResultResponse(BaseModel):
    id: int
    target_id: int
    provider_id: Optional[int] = None
    latency_ms: float
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    loss_percent: float
    jitter_ms: float
    hops: int
    status: str
    egress_mode: str = "os_routing"
    data_source: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class ProbeWorkerStatusResponse(BaseModel):
    is_running: bool
    interval_seconds: int
    concurrency_limit: int
    completed_cycles: int
    total_attempted: int
    total_successful: int
    total_failed: int
    total_timeouts: int
    last_sweep_duration_ms: float
    in_flight_probes_count: int


class EgressCapabilitiesResponse(BaseModel):
    platform: str
    so_bindtodevice_supported: bool
    source_ip_bind_supported: bool
    os_routing_fallback_supported: bool
    recommended_mode: str
    documentation: Dict[str, str]
    environment_caveat: str


from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


# Site Schemas
class SiteBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    code: str = Field(..., min_length=2, max_length=20)
    location: Optional[str] = None
    status: str = "active"


class SiteCreate(SiteBase):
    pass


class SiteResponse(SiteBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


# Provider Schemas
class ProviderBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider_asn: int = Field(..., gt=0)
    cost_weight: float = Field(default=1.0, ge=0.0)
    capacity_bps: int = Field(default=10_000_000_000, gt=0)
    status: str = "active"


class ProviderCreate(ProviderBase):
    pass


class ProviderResponse(ProviderBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


# SNMP Profile Schemas
class SNMPProfileBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    version: str = Field("v3", pattern="^(v2c|v3)$")
    port: int = Field(161, ge=1, le=65535)
    timeout_sec: float = Field(3.0, gt=0, le=30.0)
    retries: int = Field(2, ge=0, le=5)
    security_name: Optional[str] = Field(None, max_length=64)
    auth_protocol: Optional[str] = Field("SHA", max_length=20)
    priv_protocol: Optional[str] = Field("AES", max_length=20)
    is_active: bool = True


class SNMPProfileCreate(SNMPProfileBase):
    auth_pass: Optional[str] = None
    priv_pass: Optional[str] = None
    community: Optional[str] = None


class SNMPProfileUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = Field(None, pattern="^(v2c|v3)$")
    port: Optional[int] = Field(None, ge=1, le=65535)
    timeout_sec: Optional[float] = Field(None, gt=0, le=30.0)
    retries: Optional[int] = Field(None, ge=0, le=5)
    security_name: Optional[str] = None
    auth_protocol: Optional[str] = None
    priv_protocol: Optional[str] = None
    auth_pass: Optional[str] = None
    priv_pass: Optional[str] = None
    community: Optional[str] = None
    is_active: Optional[bool] = None


class SNMPProfileResponse(SNMPProfileBase):
    id: int
    has_auth_pass: bool = False
    has_priv_pass: bool = False
    has_community: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


# Interface Schemas
class InterfaceBase(BaseModel):
    if_index: int
    if_name: str
    alias: Optional[str] = None
    speed_bps: int = 1_000_000_000
    admin_status: str = "up"
    oper_status: str = "up"


class InterfaceCreate(InterfaceBase):
    device_id: int


class InterfaceResponse(InterfaceBase):
    id: int
    device_id: int
    in_bps: int = 0
    out_bps: int = 0
    in_pps: int = 0
    out_pps: int = 0
    utilization_pct: float = 0.0
    last_polled_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class InterfaceMetricsHistoryResponse(BaseModel):
    id: int
    interface_id: int
    device_id: int
    timestamp: datetime
    in_bps: int
    out_bps: int
    in_pps: int
    out_pps: int
    utilization_pct: float
    oper_status: str

    model_config = {"from_attributes": True}


# Device Schemas
class DeviceBase(BaseModel):
    hostname: str = Field(..., min_length=2, max_length=128)
    mgmt_ip: str
    vendor: str = "Generic"
    model: Optional[str] = None
    site_id: Optional[int] = None
    snmp_profile_id: Optional[int] = None
    status: str = "online"


class DeviceCreate(DeviceBase):
    pass


class DeviceResponse(DeviceBase):
    id: int
    snmp_status: str = "unconfigured"
    sys_uptime: Optional[int] = None
    sys_descr: Optional[str] = None
    last_polled_at: Optional[datetime] = None
    last_poll_duration_ms: Optional[float] = None
    last_poll_error: Optional[str] = None
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    interfaces: List[InterfaceResponse] = []

    model_config = {"from_attributes": True}


class DevicePollResponse(BaseModel):
    device_id: int
    hostname: str
    mgmt_ip: str
    success: bool
    snmp_status: str
    sys_uptime: Optional[int] = None
    sys_descr: Optional[str] = None
    duration_ms: float = 0.0
    error_message: Optional[str] = None
    interfaces_polled: int = 0


class SNMPWorkerStatusResponse(BaseModel):
    is_running: bool
    polling_interval_seconds: int
    concurrency_limit: int
    total_cycles: int
    total_polls_succeeded: int
    total_polls_failed: int
    active_in_flight_polls: int
    last_cycle_duration_ms: float
    last_cycle_at: Optional[datetime] = None
    last_cycle_devices_count: int


# Collector Schemas
class CollectorBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    host: str
    port: int
    collector_type: str = "netflow"
    site_id: Optional[int] = None
    status: str = "active"


class CollectorCreate(CollectorBase):
    pass


class CollectorResponse(CollectorBase):
    id: int
    packets_received: int
    flows_parsed: int
    parse_errors: int
    last_seen_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

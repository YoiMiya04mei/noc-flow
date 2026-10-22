from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class BGPPeerBase(BaseModel):
    peer_ip: str
    local_as: int
    remote_as: int
    peer_name: Optional[str] = None
    state: str = "Established"
    uptime_seconds: int = 0
    prefixes_received: int = 0
    prefixes_advertised: int = 0
    router_id: Optional[str] = None
    last_error: Optional[str] = None
    data_source: str = "simulated"


class BGPPeerCreate(BGPPeerBase):
    device_id: Optional[int] = None


class BGPPeerResponse(BGPPeerBase):
    id: int
    device_id: Optional[int] = None
    last_change_at: datetime

    model_config = {"from_attributes": True}


class RouteEventBase(BaseModel):
    peer_ip: str
    event_type: str
    prefix: str
    as_path: Optional[str] = None
    next_hop: Optional[str] = None
    communities: Optional[str] = None
    data_source: str = "simulated"


class RouteEventResponse(RouteEventBase):
    id: int
    timestamp: datetime

    model_config = {"from_attributes": True}


class BGPRouteBase(BaseModel):
    prefix: str
    peer_ip: str
    peer_asn: int
    best_path: Optional[str] = None
    next_hop: Optional[str] = None
    as_path: Optional[str] = None
    origin: str = "IGP"
    med: Optional[int] = None
    local_pref: Optional[int] = None
    communities: Optional[str] = None
    data_source: str = "simulated"
    is_active: bool = True


class BGPRouteResponse(BGPRouteBase):
    id: int
    last_updated: datetime

    model_config = {"from_attributes": True}


class BMPStatusResponse(BaseModel):
    is_running: bool
    host: str
    port: int
    enabled: bool
    active_connections: int
    total_messages_received: int
    total_parse_errors: int
    total_route_events: int
    total_peer_updates: int
    last_message_at: Optional[datetime] = None
    supported_message_types: List[str]
    lab_mode: bool


class BMPSimulateRequest(BaseModel):
    message_type: str = Field(default="route_monitoring", description="initiation, peer_up, route_monitoring, peer_down")
    peer_ip: str = "198.51.100.1"
    peer_asn: int = 7713
    prefix: Optional[str] = "1.1.1.0/24"
    next_hop: Optional[str] = "198.51.100.1"
    as_path: Optional[str] = "64500 13335"
    communities: Optional[str] = "64500:100"
    is_withdraw: bool = False


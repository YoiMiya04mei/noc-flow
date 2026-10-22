from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class LabPeerStatus(BaseModel):
    peer_ip: str
    peer_as: int
    local_as: int
    state: str  # Established, Active, Idle, etc.
    uptime_seconds: int
    prefixes_received: int
    prefixes_advertised: int
    router_id: Optional[str] = None


class LabSpeakerStatus(BaseModel):
    speaker_id: str
    name: str
    asn: int
    ip_address: str
    is_healthy: bool
    status_detail: str
    peers: List[LabPeerStatus] = []
    active_routes_count: int = 0


class LabStatusResponse(BaseModel):
    lab_enabled: bool
    lab_mode: bool
    speakers: List[LabSpeakerStatus]
    allowed_prefixes: List[str]
    allowed_peers: List[str]
    active_tests_count: int = 0


class PreCheckItem(BaseModel):
    check_name: str
    status: str  # PASS, FAIL
    details: str


class PreCheckReport(BaseModel):
    overall_status: str  # PASS, FAIL
    items: List[PreCheckItem]


class PostCheckReport(BaseModel):
    overall_status: str  # PASS, FAIL
    convergence_time_seconds: float
    details: Dict[str, Any] = {}


class LabTestRequest(BaseModel):
    prefix: str = Field(..., description="Target test prefix (must be in BGP_LAB_ALLOWED_PREFIXES)")
    target_speaker: str = Field("bgp-speaker-1", description="Speaker initiating the test (bgp-speaker-1 or bgp-speaker-2)")
    change_request_id: Optional[int] = Field(None, description="Optional linked change request ID")


class LabTestRunResponse(BaseModel):
    id: int
    change_request_id: Optional[int] = None
    test_type: str
    target_speaker: str
    target_peer: str
    prefix: str
    pre_check_status: str
    pre_check_details: Optional[str] = None
    post_check_status: str
    post_check_details: Optional[str] = None
    execution_status: str
    rollback_status: str
    rollback_details: Optional[str] = None
    initial_snapshot: Optional[str] = None
    final_snapshot: Optional[str] = None
    error_message: Optional[str] = None
    operator_id: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ManualReviewRequest(BaseModel):
    notes: str = Field(..., min_length=3, description="Operator explanation for completing manual review")

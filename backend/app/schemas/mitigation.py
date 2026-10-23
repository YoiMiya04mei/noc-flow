from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import ipaddress


class ThreatCandidateBase(BaseModel):
    threat_type: str = Field(..., description="Type of threat anomaly: pps_spike, bps_flood, syn_flood, port_scan, udp_amplification")
    severity: str = Field("HIGH", description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    target_prefix: str = Field(..., description="Target IPv4/IPv6 prefix under attack")
    source_prefix: Optional[str] = Field(None, description="Attacking source prefix if identifiable")
    protocol: Optional[int] = Field(None, description="IP protocol: 6=TCP, 17=UDP, 1=ICMP")
    target_port: Optional[int] = Field(None, description="Victim destination port")
    source_port: Optional[int] = Field(None, description="Attacker source port")
    detected_bps: float = Field(0.0, description="Detected attack rate in bits per second")
    detected_pps: float = Field(0.0, description="Detected attack rate in packets per second")
    confidence_score: float = Field(85.0, ge=0.0, le=100.0, description="Threat detection confidence %")
    recommended_action: str = Field("flowspec_rate_limit", description="Recommended mitigation action")
    evidence_summary: Dict[str, Any] = Field(default_factory=dict, description="Structured evidence details")
    ttl_minutes: int = Field(60, ge=5, le=1440, description="Mitigation lifetime in minutes")


class ThreatCandidateCreate(ThreatCandidateBase):
    pass


class ThreatCandidateResponse(BaseModel):
    id: int
    threat_type: str
    severity: str
    target_prefix: str
    source_prefix: Optional[str] = None
    protocol: Optional[int] = None
    target_port: Optional[int] = None
    source_port: Optional[int] = None
    detected_bps: float
    detected_pps: float
    confidence_score: float
    status: str
    evidence_summary: str
    recommended_action: str
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class FlowSpecRulePreview(BaseModel):
    match_destination_prefix: str
    match_source_prefix: Optional[str] = None
    match_protocol: Optional[int] = None
    match_destination_ports: Optional[str] = None
    match_source_ports: Optional[str] = None
    match_tcp_flags: Optional[str] = None
    action_type: str = Field(..., description="RATE_LIMIT, DISCARD, REDIRECT_VRF, MARK_DSCP")
    action_rate_bytes_per_sec: Optional[int] = None
    formatted_junos: str
    formatted_gobgp: Dict[str, Any]
    formatted_cisco: str
    validation_status: str
    validation_messages: List[str]
    rule_complexity_score: int
    expires_at: datetime


class FlowSpecRuleCreate(BaseModel):
    threat_id: Optional[int] = None
    target_prefix: str = Field(..., description="Target destination prefix (e.g., 10.100.1.0/24)")
    source_prefix: Optional[str] = Field(None, description="Source prefix to filter")
    protocol: Optional[int] = Field(None, description="IP protocol: 6 for TCP, 17 for UDP, 1 for ICMP")
    src_port_range: Optional[str] = Field(None, description="Source port or range (e.g. 53, 123, 1024-65535)")
    dst_port_range: Optional[str] = Field(None, description="Destination port or range (e.g. 80, 443, 8080)")
    tcp_flags: Optional[str] = Field(None, description="TCP flags to match (e.g. SYN, RST)")
    action_type: str = Field("RATE_LIMIT", description="RATE_LIMIT, DISCARD, REDIRECT_VRF, MARK_DSCP")
    action_value: Optional[str] = Field("1000000", description="Rate limit bps or VRF target")
    ttl_minutes: int = Field(60, ge=5, le=1440, description="TTL duration in minutes")
    withdrawal_plan: str = Field("Auto-withdraw via FlowSpec withdrawal NLRI upon TTL expiration or emergency stop.", description="Explicit recovery plan")

    @field_validator("target_prefix")
    def validate_target_prefix(cls, v: str) -> str:
        if v in ("0.0.0.0/0", "::/0"):
            raise ValueError("Default route 0.0.0.0/0 and ::/0 are permanently rejected.")
        try:
            ipaddress.ip_network(v, strict=False)
        except Exception as e:
            raise ValueError(f"Invalid IP prefix format: {str(e)}")
        return v


class RTBHRulePreview(BaseModel):
    target_prefix: str
    prefix_length: int
    is_host_route: bool
    blackhole_community: str
    next_hop: str
    upstream_peers: List[str]
    formatted_bgp_update: Dict[str, Any]
    validation_status: str
    validation_messages: List[str]
    expires_at: datetime
    withdrawal_plan: str


class RTBHRuleCreate(BaseModel):
    threat_id: Optional[int] = None
    target_prefix: str = Field(..., description="Target host or subnet to blackhole (allowed range /24 to /32 for IPv4, host /32 recommended)")
    blackhole_community: str = Field("65535:666", description="RFC 7999 BGP BLACKHOLE community")
    ttl_minutes: int = Field(60, ge=10, le=1440, description="Mitigation TTL in minutes")
    justification: str = Field(..., min_length=10, description="Operational justification for dropping traffic")
    withdrawal_plan: str = Field("Send BGP WITHDRAW update for blackhole route when threat ceases or TTL expires.", description="Explicit recovery plan")

    @field_validator("target_prefix")
    def validate_rtbh_prefix(cls, v: str) -> str:
        if v in ("0.0.0.0/0", "::/0"):
            raise ValueError("Default route cannot be targeted for RTBH.")
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.version == 4:
                if net.prefixlen < 24 or net.prefixlen > 32:
                    raise ValueError(f"Prefix length /{net.prefixlen} is too broad for RTBH. Minimum allowed is /24, recommended /32.")
            elif net.version == 6:
                if net.prefixlen < 64 or net.prefixlen > 128:
                    raise ValueError(f"IPv6 prefix length /{net.prefixlen} is too broad for RTBH. Minimum allowed is /64, recommended /128.")
        except Exception as e:
            raise ValueError(f"Invalid IP prefix format: {str(e)}")
        return v


class MitigationRuleResponse(BaseModel):
    id: int
    threat_id: Optional[int] = None
    change_request_id: Optional[int] = None
    rule_type: str
    target_prefix: str
    source_prefix: Optional[str] = None
    protocol: Optional[int] = None
    src_port_range: Optional[str] = None
    dst_port_range: Optional[str] = None
    tcp_flags: Optional[str] = None
    action_type: str
    action_value: Optional[str] = None
    status: str
    ttl_minutes: int
    expires_at: Optional[datetime] = None
    withdrawal_plan: str
    created_by_id: int
    approved_by_id: Optional[int] = None
    second_approved_by_id: Optional[int] = None
    created_at: datetime
    activated_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RolloutPlanCreate(BaseModel):
    change_request_id: Optional[int] = None
    mitigation_rule_id: Optional[int] = None
    rollout_type: str = Field("CANARY", description="CANARY, STAGED, FULL, SIMULATION_ONLY")
    total_stages: int = Field(3, ge=1, le=5, description="Number of progressive stages")
    scope_prefixes: List[str] = Field(..., description="List of CIDRs included in this rollout")
    change_window_start: Optional[datetime] = None
    change_window_end: Optional[datetime] = None


class RolloutPlanResponse(BaseModel):
    id: int
    change_request_id: Optional[int] = None
    mitigation_rule_id: Optional[int] = None
    rollout_type: str
    current_stage: int
    total_stages: int
    status: str
    scope_prefixes: str
    change_window_start: Optional[datetime] = None
    change_window_end: Optional[datetime] = None
    pre_check_report: Optional[str] = None
    post_check_report: Optional[str] = None
    rollback_details: Optional[str] = None
    correlation_id: str
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ExecutionGateItem(BaseModel):
    criterion: str
    status: str  # PASS, FAIL, BLOCKED
    details: str


class ExecutionGateReport(BaseModel):
    overall_status: str  # PERMITTED, BLOCKED
    is_production_ready: bool
    summary: str
    items: List[ExecutionGateItem]


class CircuitBreakerStatusResponse(BaseModel):
    state: str  # CLOSED, OPEN, HALF_OPEN
    scope: str
    is_execution_blocked: bool
    consecutive_failures: int
    failure_threshold: int
    last_trigger_reason: Optional[str] = None
    last_triggered_at: Optional[datetime] = None
    emergency_stop_active: bool


class CircuitBreakerTriggerRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Reason for triggering circuit breaker")
    scope: str = Field("GLOBAL", description="Scope: GLOBAL, PREFIX, PEER, ADAPTER")
    scope_target: Optional[str] = Field(None, description="Target prefix or peer if scoped")


class CircuitBreakerResetRequest(BaseModel):
    notes: str = Field(..., min_length=10, description="Mandatory operator explanation of root cause resolution")


class EmergencyStopRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Emergency stop rationale")


class EmergencyStopResponse(BaseModel):
    status: str
    message: str
    emergency_stop_active: bool
    timestamp: datetime

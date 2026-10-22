from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class ThreatCandidate(Base):
    __tablename__ = "threat_candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False)  # pps_spike, bps_flood, syn_flood, port_scan, udp_amplification
    severity: Mapped[str] = mapped_column(String(20), default="HIGH", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    target_prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    source_prefix: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 6=TCP, 17=UDP, 1=ICMP
    target_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detected_bps: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    detected_pps: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=85.0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default="DETECTED", nullable=False
    )  # DETECTED, ANALYZING, CANDIDATE_FORMED, MITIGATED, IGNORED, EXPIRED
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)  # JSON summary of flow packets, exporter, timing
    recommended_action: Mapped[str] = mapped_column(String(50), default="flowspec_rate_limit", nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MitigationRule(Base):
    __tablename__ = "mitigation_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    threat_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("threat_candidates.id", ondelete="SET NULL"), nullable=True)
    change_request_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("change_requests.id", ondelete="SET NULL"), nullable=True)
    
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False)  # FLOWSPEC, RTBH
    target_prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    source_prefix: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    src_port_range: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    dst_port_range: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    tcp_flags: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    action_type: Mapped[str] = mapped_column(String(30), nullable=False)  # RATE_LIMIT, DISCARD, REDIRECT_VRF, MARK_DSCP, BLACKHOLE
    action_value: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # rate limit bps/pps, community e.g. 65535:666
    
    status: Mapped[str] = mapped_column(
        String(30), default="DRAFT", nullable=False
    )  # DRAFT, POLICY_VALIDATED, LAB_TESTED, AWAITING_APPROVAL, APPROVED, SCHEDULED, EXECUTING, ACTIVE, WITHDRAWN, EXPIRED, CANCELLED
    
    ttl_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    withdrawal_plan: Mapped[str] = mapped_column(Text, nullable=False)
    
    created_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    second_approved_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    withdrawn_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RolloutExecution(Base):
    __tablename__ = "rollout_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    change_request_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("change_requests.id", ondelete="SET NULL"), nullable=True)
    mitigation_rule_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("mitigation_rules.id", ondelete="SET NULL"), nullable=True)
    
    rollout_type: Mapped[str] = mapped_column(String(30), default="CANARY", nullable=False)  # CANARY, STAGED, FULL, SIMULATION_ONLY
    current_stage: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    total_stages: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    
    status: Mapped[str] = mapped_column(
        String(30), default="DRAFT", nullable=False
    )  # DRAFT, POLICY_VALIDATED, LAB_TESTED, AWAITING_APPROVAL, APPROVED, SCHEDULED, PRE_CHECK, EXECUTING, POST_CHECK, COMPLETED, FAILED, ROLLBACK_PENDING, ROLLED_BACK, NEEDS_MANUAL_REVIEW, CANCELLED, EXPIRED
    
    scope_prefixes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of CIDRs
    change_window_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    change_window_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    pre_check_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON 12-point report
    post_check_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    rollback_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    correlation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class CircuitBreakerEvent(Base):
    __tablename__ = "circuit_breaker_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    scope: Mapped[str] = mapped_column(String(30), default="GLOBAL", nullable=False)  # GLOBAL, PREFIX, PEER, ADAPTER
    scope_target: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="CLOSED", nullable=False)  # CLOSED, OPEN, HALF_OPEN
    trigger_reason: Mapped[str] = mapped_column(Text, nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    triggered_by: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # SYSTEM_DETECTOR, EMERGENCY_STOP
    
    reset_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    reset_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    reset_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

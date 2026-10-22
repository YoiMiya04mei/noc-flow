from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    current_path: Mapped[str] = mapped_column(String(128), nullable=False)
    candidate_path: Mapped[str] = mapped_column(String(128), nullable=False)
    score_current: Mapped[float] = mapped_column(Float, nullable=False)
    score_candidate: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_pct: Mapped[float] = mapped_column(Float, default=85.0, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)  # low, medium, high
    status: Mapped[str] = mapped_column(
        String(30), default="generated", nullable=False
    )  # generated, under_review, approved, rejected, superseded, expired, cancelled
    
    # Phase 5 Extensions
    policy_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scoring_policies.id"), nullable=True)
    score_breakdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: per-metric contributions
    current_metrics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: latency, loss, jitter, util, cost
    candidate_metrics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: latency, loss, jitter, util, cost
    data_quality: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: freshness, sources, completeness
    rejection_reasons: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: why alternatives rejected
    input_snapshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA-256 for reproducibility
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ChangeRequest(Base):
    __tablename__ = "change_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    recommendation_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("recommendations.id"), nullable=True)
    requester_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    approver_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    second_approver_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)  # Dual-approval
    
    target_peer: Mapped[str] = mapped_column(String(45), nullable=False)
    prefix: Mapped[str] = mapped_column(String(50), nullable=False)
    diff_payload: Mapped[str] = mapped_column(Text, nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(30), default="valid", nullable=False)
    execution_status: Mapped[str] = mapped_column(
        String(30), default="pending_approval", nullable=False
    )  # draft, pending_approval, partially_approved, approved, rejected, executed, rolled_back, cancelled
    rollback_instructions: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Phase 5 Extensions
    requires_dual_approval: Mapped[bool] = mapped_column(default=True, nullable=False)
    policy_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: policy rule check at approval
    impact_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: expected delta
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_cancelled: Mapped[bool] = mapped_column(default=False, nullable=False)
    cancellation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Phase 6 Extensions: Lab Verification Evidence
    lab_tested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    lab_test_run_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("lab_test_runs.id", ondelete="SET NULL", use_alter=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    second_approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

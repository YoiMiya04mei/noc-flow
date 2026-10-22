from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class LabTestRun(Base):
    __tablename__ = "lab_test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    change_request_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("change_requests.id", ondelete="SET NULL"), nullable=True, index=True
    )
    test_type: Mapped[str] = mapped_column(String(30), nullable=False)  # ANNOUNCE, WITHDRAW, ROUNDTRIP
    target_speaker: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "bgp-speaker-1"
    target_peer: Mapped[str] = mapped_column(String(45), nullable=False)  # e.g. "10.99.0.20"
    prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)

    pre_check_status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)  # PASS, FAIL, PENDING
    pre_check_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of 11 checks

    post_check_status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)  # PASS, FAIL, PENDING
    post_check_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON details

    execution_status: Mapped[str] = mapped_column(
        String(30), default="PENDING", nullable=False
    )  # PENDING, SUCCESS, FAILED, ROLLED_BACK

    rollback_status: Mapped[str] = mapped_column(
        String(30), default="NONE", nullable=False
    )  # NONE, PENDING, ROLLBACK_SUCCEEDED, ROLLBACK_FAILED, NEEDS_MANUAL_REVIEW
    rollback_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON details

    initial_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: receiver RIB before
    final_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: receiver RIB after

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    operator_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

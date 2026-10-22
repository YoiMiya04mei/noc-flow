from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class ProbeTarget(Base):
    __tablename__ = "probe_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    target_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    target_name: Mapped[str] = mapped_column(String(100), nullable=False)
    probe_type: Mapped[str] = mapped_column(String(20), default="icmp", nullable=False) # icmp, tcp, udp
    port: Mapped[Optional[int]] = mapped_column(Integer, default=80, nullable=True) # Used for tcp connect probes
    provider_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("providers.id"), nullable=True)
    egress_interface: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True) # Source IP binding
    interval_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=2000, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_probed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_loss_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_status: Mapped[str] = mapped_column(String(30), default="standby", nullable=False) # ok, degraded, timeout, stale, standby
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ProbeResult(Base):
    __tablename__ = "probe_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("probe_targets.id"), nullable=False, index=True)
    provider_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("providers.id"), nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    min_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    max_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    loss_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    jitter_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    hops: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ok", nullable=False) # ok, degraded, timeout, unreachable
    egress_mode: Mapped[str] = mapped_column(String(30), default="os_routing", nullable=False) # so_bindtodevice, source_ip_bind, os_routing
    data_source: Mapped[str] = mapped_column(String(30), default="simulated", nullable=False) # live, lab, simulated
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


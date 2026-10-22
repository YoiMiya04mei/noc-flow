from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class PrefixAllowlist(Base):
    __tablename__ = "prefix_allowlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    prefix: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class PeerAllowlist(Base):
    __tablename__ = "peer_allowlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    peer_ip: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    peer_asn: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ScoringPolicy(Base):
    __tablename__ = "scoring_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    latency_weight: Mapped[float] = mapped_column(Float, default=0.35, nullable=False)
    loss_weight: Mapped[float] = mapped_column(Float, default=0.30, nullable=False)
    jitter_weight: Mapped[float] = mapped_column(Float, default=0.15, nullable=False)
    cost_weight: Mapped[float] = mapped_column(Float, default=0.10, nullable=False)
    utilization_weight: Mapped[float] = mapped_column(Float, default=0.10, nullable=False)
    hold_down_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    hysteresis_threshold_pct: Mapped[float] = mapped_column(Float, default=15.0, nullable=False)
    min_improvement_score: Mapped[float] = mapped_column(Float, default=10.0, nullable=False)
    max_acceptable_loss_pct: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)
    max_acceptable_latency_ms: Mapped[float] = mapped_column(Float, default=250.0, nullable=False)
    max_utilization_pct: Mapped[float] = mapped_column(Float, default=90.0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

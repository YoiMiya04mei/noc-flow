from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class BGPPeer(Base):
    __tablename__ = "bgp_peers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("devices.id"), nullable=True)
    peer_ip: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    local_as: Mapped[int] = mapped_column(BigInteger, nullable=False)
    remote_as: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    peer_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[str] = mapped_column(String(30), default="Established", nullable=False) # Established, Active, Idle, Connect
    uptime_seconds: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    prefixes_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    prefixes_advertised: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    router_id: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_source: Mapped[str] = mapped_column(String(30), default="simulated", nullable=False) # live, lab, simulated, stale
    last_change_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class RouteEvent(Base):
    __tablename__ = "route_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    peer_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False) # ANNOUNCE, WITHDRAW, FLAP, STATE_CHANGE
    prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    as_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    next_hop: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    communities: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_source: Mapped[str] = mapped_column(String(30), default="simulated", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class BGPRoute(Base):
    __tablename__ = "bgp_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    prefix: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    peer_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    peer_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    best_path: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    next_hop: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    as_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    origin: Mapped[str] = mapped_column(String(20), default="IGP", nullable=False)
    med: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    local_pref: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    communities: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_source: Mapped[str] = mapped_column(String(30), default="simulated", nullable=False) # live, lab, simulated
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, BigInteger, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    location: Mapped[str] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    devices: Mapped[List["Device"]] = relationship("Device", back_populates="site", cascade="all, delete-orphan")


class Provider(Base):
    __tablename__ = "providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    provider_asn: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    cost_weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    capacity_bps: Mapped[int] = mapped_column(BigInteger, default=10_000_000_000, nullable=False) # 10G default
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class SNMPProfile(Base):
    __tablename__ = "snmp_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(10), default="v3", nullable=False) # 'v2c', 'v3'
    port: Mapped[int] = mapped_column(Integer, default=161, nullable=False)
    timeout_sec: Mapped[float] = mapped_column(Float, default=3.0, nullable=False)
    retries: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    security_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True) # SNMPv3 username
    auth_protocol: Mapped[Optional[str]] = mapped_column(String(20), default="SHA", nullable=True) # SHA, MD5, SHA-256, NONE
    auth_pass_encrypted: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    priv_protocol: Mapped[Optional[str]] = mapped_column(String(20), default="AES", nullable=True) # AES, DES, AES-256, NONE
    priv_pass_encrypted: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    community_encrypted: Mapped[Optional[str]] = mapped_column(String(512), nullable=True) # SNMPv2c community
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    devices: Mapped[List["Device"]] = relationship("Device", back_populates="snmp_profile")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    mgmt_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    vendor: Mapped[str] = mapped_column(String(64), default="Generic", nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=True)
    site_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("sites.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="online", nullable=False)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # SNMP Polling state & telemetry
    snmp_profile_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("snmp_profiles.id", ondelete="SET NULL"), nullable=True)
    snmp_status: Mapped[str] = mapped_column(String(30), default="unconfigured", nullable=False) # unconfigured, ok, timeout, auth_error, error, stale
    sys_uptime: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True) # hundredths of a second
    sys_descr: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_polled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_poll_error: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    site: Mapped[Optional["Site"]] = relationship("Site", back_populates="devices")
    snmp_profile: Mapped[Optional["SNMPProfile"]] = relationship("SNMPProfile", back_populates="devices")
    interfaces: Mapped[List["Interface"]] = relationship("Interface", back_populates="device", cascade="all, delete-orphan")
    metrics_history: Mapped[List["InterfaceMetricsHistory"]] = relationship("InterfaceMetricsHistory", back_populates="device", cascade="all, delete-orphan")


class Interface(Base):
    __tablename__ = "interfaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    if_index: Mapped[int] = mapped_column(Integer, nullable=False)
    if_name: Mapped[str] = mapped_column(String(64), nullable=False)
    alias: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    speed_bps: Mapped[int] = mapped_column(BigInteger, default=1_000_000_000, nullable=False) # 1G default
    admin_status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)
    oper_status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)
    in_bps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    out_bps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    in_pps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    out_pps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    utilization_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_polled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Counter raw baselines for delta computation
    last_in_octets: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_out_octets: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_in_pkts: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_out_pkts: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_uptime: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    device: Mapped["Device"] = relationship("Device", back_populates="interfaces")
    metrics_history: Mapped[List["InterfaceMetricsHistory"]] = relationship("InterfaceMetricsHistory", back_populates="interface", cascade="all, delete-orphan")


class InterfaceMetricsHistory(Base):
    __tablename__ = "interface_metrics_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    interface_id: Mapped[int] = mapped_column(Integer, ForeignKey("interfaces.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    in_bps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    out_bps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    in_pps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    out_pps: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    utilization_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    oper_status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)

    interface: Mapped["Interface"] = relationship("Interface", back_populates="metrics_history")
    device: Mapped["Device"] = relationship("Device", back_populates="metrics_history")


class Collector(Base):
    __tablename__ = "collectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    host: Mapped[str] = mapped_column(String(128), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    collector_type: Mapped[str] = mapped_column(String(30), default="netflow", nullable=False) # netflow, sflow, ipfix
    site_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("sites.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    packets_received: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    flows_parsed: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    parse_errors: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

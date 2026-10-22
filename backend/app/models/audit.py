from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class AuditEvent(Base):
    """
    Append-only audit trail for all security, operational, and routing changes.
    Raw secrets (passwords, SNMP auth keys, BGP MD5 keys) must never be recorded.
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    actor_username: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False) # LOGIN, LOGOUT, CREATE, UPDATE, DELETE, SIMULATE, APPROVE, REJECT, EXECUTE, ROLLBACK
    resource_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False) # user, device, policy, recommendation, change_request, peer
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

from datetime import datetime, timezone
import enum
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    NETWORK_ENGINEER = "network_engineer"
    APPROVER = "approver"
    NOC_OPERATOR = "noc_operator"
    AUDITOR = "auditor"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default=UserRole.NOC_OPERATOR.value, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=UserStatus.ACTIVE.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

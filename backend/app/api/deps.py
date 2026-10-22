from typing import AsyncGenerator, Callable, List, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import jwt

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User, UserRole, UserStatus
from app.models.audit import AuditEvent

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    if not user.is_active or user.status != UserStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive or suspended user account",
        )
    return user


def require_roles(*allowed_roles: UserRole) -> Callable:
    """
    Role-Based Access Control (RBAC) Dependency.
    Super Admin always has access to all authorized endpoints.
    """
    allowed_role_values = [r.value for r in allowed_roles]

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role == UserRole.SUPER_ADMIN.value:
            return current_user
        if current_user.role not in allowed_role_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{current_user.role}' lacks permission for this operation.",
            )
        return current_user

    return role_checker


def check_routing_execution_guardrail():
    """
    Critical Routing Safety Guardrail.
    Blocks route execution if ROUTING_EXECUTION_ENABLED is False.
    """
    if not settings.ROUTING_EXECUTION_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "SAFETY GUARDRAIL ENFORCED: ROUTING_EXECUTION_ENABLED is FALSE. "
                "Automatic router execution is locked. Use lab simulation or request admin enablement."
            ),
        )


async def record_audit_event(
    db: AsyncSession,
    user: Optional[User],
    action: str,
    resource_type: str,
    resource_id: str = None,
    details: str = None,
    request: Request = None,
):
    ip_addr = request.client.host if request and request.client else "127.0.0.1"
    actor_username = user.username if user else "system"
    actor_role = user.role if user else "SYSTEM"
    event = AuditEvent(
        actor_username=actor_username,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=details,
        ip_address=ip_addr,
    )
    db.add(event)
    await db.commit()

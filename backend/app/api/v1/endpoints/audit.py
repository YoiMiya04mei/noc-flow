from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.audit import AuditEvent
from app.schemas.audit import AuditEventResponse
from app.api.deps import get_current_user, require_roles

router = APIRouter()


@router.get("", response_model=List[AuditEventResponse])
async def list_audit_events(
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.AUDITOR)),
):
    stmt = select(AuditEvent)
    if actor:
        stmt = stmt.where(AuditEvent.actor_username == actor)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)

    stmt = stmt.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit)
    events = (await db.execute(stmt)).scalars().all()
    return events

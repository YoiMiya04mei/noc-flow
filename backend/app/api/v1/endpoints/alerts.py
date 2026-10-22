from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.alert import AlertIncident, AlertRule
from app.schemas.alert import (
    AlertIncidentResponse,
    AlertAcknowledgeRequest,
    AlertRuleResponse,
    AlertRuleCreate,
)
from app.api.deps import get_current_user, require_roles, record_audit_event

router = APIRouter()


@router.get("", response_model=List[AlertIncidentResponse])
async def list_active_alerts(
    status_filter: Optional[str] = Query(None),
    severity_filter: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AlertIncident)
    if status_filter:
        stmt = stmt.where(AlertIncident.status == status_filter)
    if severity_filter:
        stmt = stmt.where(AlertIncident.severity == severity_filter)
    stmt = stmt.order_by(AlertIncident.started_at.desc())
    incidents = (await db.execute(stmt)).scalars().all()
    return incidents


@router.get("/rules", response_model=List[AlertRuleResponse])
async def list_alert_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AlertRule).order_by(AlertRule.id.asc())
    rules = (await db.execute(stmt)).scalars().all()
    return rules


@router.post("/{incident_id}/ack", response_model=AlertIncidentResponse)
async def acknowledge_alert(
    incident_id: int,
    payload: AlertAcknowledgeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AlertIncident).where(AlertIncident.id == incident_id)
    incident = (await db.execute(stmt)).scalars().first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert incident not found")

    incident.status = "acknowledged"
    incident.acknowledged_by = current_user.username
    incident.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(incident)

    await record_audit_event(
        db=db,
        user=current_user,
        action="ACKNOWLEDGE_ALERT",
        resource_type="alert_incident",
        resource_id=str(incident.id),
        details=f"Alert {incident.title} acknowledged. Notes: {payload.notes or 'None'}",
        request=request,
    )
    return incident

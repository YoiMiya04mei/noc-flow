from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.inventory import Collector
from app.schemas.inventory import CollectorCreate, CollectorResponse
from app.api.deps import get_current_user, require_roles, record_audit_event

router = APIRouter()


@router.get("", response_model=List[CollectorResponse])
async def list_collectors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Collector).order_by(Collector.id.asc())
    collectors = (await db.execute(stmt)).scalars().all()
    return collectors


@router.post("", response_model=CollectorResponse, status_code=status.HTTP_201_CREATED)
async def create_collector(
    payload: CollectorCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    collector = Collector(
        name=payload.name,
        host=payload.host,
        port=payload.port,
        collector_type=payload.collector_type,
        site_id=payload.site_id,
        status=payload.status,
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(collector)
    await db.commit()
    await db.refresh(collector)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_COLLECTOR",
        resource_type="collector",
        resource_id=str(collector.id),
        details=f"Collector {collector.name} ({collector.collector_type}:{collector.port}) registered.",
        request=request,
    )
    return collector


@router.get("/{collector_id}/health")
async def get_collector_health(
    collector_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Collector).where(Collector.id == collector_id)
    collector = (await db.execute(stmt)).scalars().first()
    if not collector:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collector not found")

    return {
        "id": collector.id,
        "name": collector.name,
        "status": collector.status,
        "packets_received": collector.packets_received,
        "flows_parsed": collector.flows_parsed,
        "parse_errors": collector.parse_errors,
        "drop_rate_pct": round(
            (collector.parse_errors / max(collector.packets_received, 1)) * 100, 3
        ),
        "last_seen_at": collector.last_seen_at,
        "health": "healthy" if collector.status == "active" else "degraded",
    }

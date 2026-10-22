from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, status, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.probe import ProbeTarget, ProbeResult
from app.schemas.probe import (
    ProbeTargetCreate,
    ProbeTargetUpdate,
    ProbeTargetResponse,
    ProbeResultResponse,
    ProbeWorkerStatusResponse,
    EgressCapabilitiesResponse,
)
from app.api.deps import get_current_user, require_roles, record_audit_event
from app.services.probe_service import probe_background_worker
from app.services.egress_binding import egress_manager

router = APIRouter()


@router.get("/targets", response_model=List[ProbeTargetResponse])
async def list_probe_targets(
    is_active: Optional[bool] = Query(None),
    provider_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns list of all configured active path probe targets."""
    stmt = select(ProbeTarget)
    if is_active is not None:
        stmt = stmt.where(ProbeTarget.is_active == is_active)
    if provider_id is not None:
        stmt = stmt.where(ProbeTarget.provider_id == provider_id)
    stmt = stmt.order_by(ProbeTarget.id.asc())
    targets = (await db.execute(stmt)).scalars().all()
    return targets


@router.post("/targets", response_model=ProbeTargetResponse, status_code=status.HTTP_201_CREATED)
async def create_probe_target(
    payload: ProbeTargetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """Creates a new active path probe target. Restricted to Network Engineers & Super Admins."""
    target = ProbeTarget(
        target_ip=payload.target_ip,
        target_name=payload.target_name,
        probe_type=payload.probe_type.lower(),
        port=payload.port if payload.probe_type.lower() == "tcp" else None,
        provider_id=payload.provider_id,
        egress_interface=payload.egress_interface,
        source_ip=payload.source_ip,
        interval_seconds=payload.interval_seconds,
        timeout_ms=payload.timeout_ms,
        is_active=payload.is_active,
        last_status="standby",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_PROBE_TARGET",
        resource_type="probe_target",
        resource_id=str(target.id),
        details=f"Target '{target.target_name}' ({target.target_ip}) configured for {target.probe_type} probing.",
        request=request,
    )
    return target


@router.put("/targets/{target_id}", response_model=ProbeTargetResponse)
async def update_probe_target(
    target_id: int,
    payload: ProbeTargetUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """Updates configuration of an existing probe target."""
    target = await db.get(ProbeTarget, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target {target_id} not found")

    if payload.target_ip is not None:
        target.target_ip = payload.target_ip
    if payload.target_name is not None:
        target.target_name = payload.target_name
    if payload.probe_type is not None:
        target.probe_type = payload.probe_type.lower()
    if payload.port is not None:
        target.port = payload.port
    if payload.provider_id is not None:
        target.provider_id = payload.provider_id
    if payload.egress_interface is not None:
        target.egress_interface = payload.egress_interface
    if payload.source_ip is not None:
        target.source_ip = payload.source_ip
    if payload.interval_seconds is not None:
        target.interval_seconds = payload.interval_seconds
    if payload.timeout_ms is not None:
        target.timeout_ms = payload.timeout_ms
    if payload.is_active is not None:
        target.is_active = payload.is_active

    await db.commit()
    await db.refresh(target)

    await record_audit_event(
        db=db,
        user=current_user,
        action="UPDATE_PROBE_TARGET",
        resource_type="probe_target",
        resource_id=str(target.id),
        details=f"Updated probe target '{target.target_name}'.",
        request=request,
    )
    return target


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_probe_target(
    target_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """Deletes a probe target."""
    target = await db.get(ProbeTarget, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target {target_id} not found")

    await db.delete(target)
    await db.commit()

    await record_audit_event(
        db=db,
        user=current_user,
        action="DELETE_PROBE_TARGET",
        resource_type="probe_target",
        resource_id=str(target_id),
        details=f"Deleted probe target id={target_id}.",
        request=request,
    )
    return None


@router.get("/results", response_model=List[ProbeResultResponse])
async def list_probe_results(
    target_id: Optional[int] = Query(None),
    provider_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns historical probe measurement results."""
    stmt = select(ProbeResult)
    if target_id:
        stmt = stmt.where(ProbeResult.target_id == target_id)
    if provider_id:
        stmt = stmt.where(ProbeResult.provider_id == provider_id)
    stmt = stmt.order_by(ProbeResult.timestamp.desc()).limit(limit)
    results = (await db.execute(stmt)).scalars().all()
    return results


@router.get("/worker-status", response_model=ProbeWorkerStatusResponse)
async def get_probe_worker_status(
    current_user: User = Depends(get_current_user),
):
    """Returns health and operational metrics of the active probing background worker."""
    return probe_background_worker.get_status()


@router.post("/execute-now")
async def execute_probe_now(
    target_id: Optional[int] = Query(None, description="Optional target ID to probe immediately"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """Triggers an on-demand active probe sweep without waiting for scheduled timer."""
    if target_id:
        target = await db.get(ProbeTarget, target_id)
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target {target_id} not found")
        res = await probe_background_worker.probe_single_target(target_id)
        return {
            "status": "success",
            "target_id": target_id,
            "target_ip": target.target_ip,
            "latency_ms": res.latency_ms if res else None,
            "loss_percent": res.loss_percent if res else None,
            "egress_mode": res.egress_mode if res else None,
        }
    else:
        await probe_background_worker.run_single_sweep()
        return {
            "status": "success",
            "message": "Immediate active probe sweep completed.",
        }


@router.get("/egress-capabilities", response_model=EgressCapabilitiesResponse)
async def get_egress_capabilities(
    current_user: User = Depends(get_current_user),
):
    """
    Returns platform-specific egress binding capabilities and limitations
    (SO_BINDTODEVICE on Linux vs Source IP binding on Windows).
    """
    return egress_manager.get_capabilities()


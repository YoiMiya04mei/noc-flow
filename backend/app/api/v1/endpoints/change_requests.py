import json
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.models.user import User, UserRole
from app.models.recommendation import ChangeRequest, Recommendation
from app.models.policy import PrefixAllowlist
from app.schemas.recommendation import (
    ChangeRequestCreate,
    ChangeRequestResponse,
    ChangeRequestApprove,
    ChangeRequestReject,
    ChangeRequestCancel,
)
from app.api.deps import (
    get_current_user,
    require_roles,
    check_routing_execution_guardrail,
    record_audit_event,
)

router = APIRouter()


@router.get("", response_model=List[ChangeRequestResponse])
async def list_change_requests(
    status: Optional[str] = Query(None, description="Filter by execution_status"),
    prefix: Optional[str] = Query(None, description="Filter by prefix"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all change requests with optional filtering.
    """
    stmt = select(ChangeRequest).order_by(ChangeRequest.id.desc())
    conditions = []
    if status:
        conditions.append(ChangeRequest.execution_status == status)
    if prefix:
        conditions.append(ChangeRequest.prefix == prefix)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.limit(limit).offset(offset)
    changes = (await db.execute(stmt)).scalars().all()
    return changes


@router.get("/{change_id}", response_model=ChangeRequestResponse)
async def get_change_request(
    change_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve details of a specific change request.
    """
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id)
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")
    return change


@router.post("", response_model=ChangeRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_change_request(
    payload: ChangeRequestCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Creates a new routing change request. Validates prefix against PrefixAllowlist.
    """
    # Guardrail check: prefix must be allowlisted
    allowlist_stmt = select(PrefixAllowlist).where(
        PrefixAllowlist.prefix == payload.prefix,
        PrefixAllowlist.is_active == True,
    )
    allowlisted = (await db.execute(allowlist_stmt)).scalars().first()
    if not allowlisted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"GUARDRAIL REJECTION: Prefix '{payload.prefix}' is not in the active PrefixAllowlist.",
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=2)

    change = ChangeRequest(
        recommendation_id=payload.recommendation_id,
        requester_id=current_user.id,
        target_peer=payload.target_peer,
        prefix=payload.prefix,
        diff_payload=payload.diff_payload,
        justification=payload.justification,
        rollback_instructions=payload.rollback_instructions,
        validation_status="valid",
        execution_status="pending_approval",
        requires_dual_approval=payload.requires_dual_approval,
        policy_snapshot=json.dumps({"allowlist_validated_at": now.isoformat(), "prefix": payload.prefix}),
        expires_at=expires_at,
        is_cancelled=False,
    )
    db.add(change)

    # If linked to a recommendation, update its status to 'under_review'
    if payload.recommendation_id:
        rec_stmt = select(Recommendation).where(Recommendation.id == payload.recommendation_id)
        rec = (await db.execute(rec_stmt)).scalars().first()
        if rec:
            rec.status = "under_review"

    await db.commit()
    await db.refresh(change)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_CHANGE_REQUEST",
        resource_type="change_request",
        resource_id=str(change.id),
        details=f"Change request for prefix {change.prefix} on peer {change.target_peer} created by {current_user.username}.",
        request=request,
    )
    return change


@router.post("/{change_id}/approve", response_model=ChangeRequestResponse)
async def approve_change_request(
    change_id: int,
    request: Request,
    payload: Optional[ChangeRequestApprove] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Approves a change request.
    Enforces:
    1. Requester cannot approve their own change request (self-approval forbidden).
    2. Dual approval rule: For sensitive changes, two distinct approver accounts must sign off.
    3. Re-validates prefix allowlist at approval time.
    4. Rejects cancelled or expired requests.
    """
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id).with_for_update()
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")

    # Check expiration and cancellation
    now = datetime.now(timezone.utc)
    if change.is_cancelled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot approve a cancelled change request.")
    if change.execution_status in ("rejected", "executed", "rolled_back"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve change request with status '{change.execution_status}'.",
        )
    if change.expires_at:
        change_exp = change.expires_at if change.expires_at.tzinfo else change.expires_at.replace(tzinfo=timezone.utc)
        if now > change_exp:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Change request has expired.")

    # 1. Anti-Self-Approval Rule: Requester cannot approve their own change request
    if change.requester_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SAFETY RULE VIOLATION: Requester cannot approve their own change request.",
        )

    # 2. Re-validate PrefixAllowlist at approval time
    allowlist_stmt = select(PrefixAllowlist).where(
        PrefixAllowlist.prefix == change.prefix,
        PrefixAllowlist.is_active == True,
    )
    allowlisted = (await db.execute(allowlist_stmt)).scalars().first()
    if not allowlisted:
        change.validation_status = "invalid"
        change.execution_status = "rejected"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"POLICY RE-VALIDATION FAILED: Prefix '{change.prefix}' is no longer in active PrefixAllowlist. Approval rejected.",
        )

    # 3. Handle Dual-Approval Workflow
    if change.requires_dual_approval:
        if change.execution_status == "pending_approval":
            # Step 1: First approval
            change.approver_id = current_user.id
            change.approved_at = now
            change.execution_status = "partially_approved"
            await db.commit()
            await db.refresh(change)

            await record_audit_event(
                db=db,
                user=current_user,
                action="APPROVE_CHANGE_REQUEST_STEP_1",
                resource_type="change_request",
                resource_id=str(change.id),
                details=f"Change request {change.id} partially approved (Step 1/2) by {current_user.username}.",
                request=request,
            )
            return change

        elif change.execution_status == "partially_approved":
            # Step 2: Second approval must be a different authorized user
            if change.approver_id == current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="DUAL APPROVAL VIOLATION: Second approval must be signed by a different approver account.",
                )
            change.second_approver_id = current_user.id
            change.second_approved_at = now
            change.execution_status = "approved"

            # Update linked recommendation if present
            if change.recommendation_id:
                rec_stmt = select(Recommendation).where(Recommendation.id == change.recommendation_id)
                rec = (await db.execute(rec_stmt)).scalars().first()
                if rec:
                    rec.status = "approved"

            await db.commit()
            await db.refresh(change)

            await record_audit_event(
                db=db,
                user=current_user,
                action="APPROVE_CHANGE_REQUEST_FINAL",
                resource_type="change_request",
                resource_id=str(change.id),
                details=f"Change request {change.id} fully approved (Step 2/2) by second approver {current_user.username}.",
                request=request,
            )
            return change

    # Single-approval path (if dual-approval not required)
    change.approver_id = current_user.id
    change.approved_at = now
    change.execution_status = "approved"
    if change.recommendation_id:
        rec_stmt = select(Recommendation).where(Recommendation.id == change.recommendation_id)
        rec = (await db.execute(rec_stmt)).scalars().first()
        if rec:
            rec.status = "approved"

    await db.commit()
    await db.refresh(change)

    await record_audit_event(
        db=db,
        user=current_user,
        action="APPROVE_CHANGE_REQUEST",
        resource_type="change_request",
        resource_id=str(change.id),
        details=f"Change request {change.id} approved by {current_user.username}.",
        request=request,
    )
    return change


@router.post("/{change_id}/reject", response_model=ChangeRequestResponse)
async def reject_change_request(
    change_id: int,
    payload: ChangeRequestReject,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Rejects a change request with explicit explanation.
    """
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id)
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")

    if change.execution_status in ("executed", "rolled_back"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject change request in status '{change.execution_status}'.",
        )

    change.execution_status = "rejected"
    change.cancellation_reason = f"Rejected by {current_user.username}: {payload.reason}"

    if change.recommendation_id:
        rec_stmt = select(Recommendation).where(Recommendation.id == change.recommendation_id)
        rec = (await db.execute(rec_stmt)).scalars().first()
        if rec:
            rec.status = "rejected"

    await db.commit()
    await db.refresh(change)

    await record_audit_event(
        db=db,
        user=current_user,
        action="REJECT_CHANGE_REQUEST",
        resource_type="change_request",
        resource_id=str(change.id),
        details=f"Change request {change.id} rejected by {current_user.username}. Reason: {payload.reason}",
        request=request,
    )
    return change


@router.post("/{change_id}/cancel", response_model=ChangeRequestResponse)
async def cancel_change_request(
    change_id: int,
    payload: ChangeRequestCancel,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Cancels a change request.
    Only the original requester, an approver, or super_admin may cancel.
    """
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id)
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")

    # Check permission to cancel
    is_owner = change.requester_id == current_user.id
    is_privileged = current_user.role in (UserRole.APPROVER.value, UserRole.SUPER_ADMIN.value)
    if not (is_owner or is_privileged):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to cancel this change request.",
        )

    if change.execution_status in ("executed", "rolled_back"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel change request with status '{change.execution_status}'.",
        )

    change.is_cancelled = True
    change.execution_status = "cancelled"
    change.cancellation_reason = f"Cancelled by {current_user.username}: {payload.reason}"

    if change.recommendation_id:
        rec_stmt = select(Recommendation).where(Recommendation.id == change.recommendation_id)
        rec = (await db.execute(rec_stmt)).scalars().first()
        if rec:
            rec.status = "cancelled"

    await db.commit()
    await db.refresh(change)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CANCEL_CHANGE_REQUEST",
        resource_type="change_request",
        resource_id=str(change.id),
        details=f"Change request {change.id} cancelled by {current_user.username}. Reason: {payload.reason}",
        request=request,
    )
    return change


@router.post("/{change_id}/execute", response_model=ChangeRequestResponse)
async def execute_change_request(
    change_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Execution endpoint permanently locked in Phase 5.
    ROUTING_EXECUTION_ENABLED is FALSE.
    """
    check_routing_execution_guardrail()
    # If guardrail were ever enabled in future phases:
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id)
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")
    return change


@router.post("/{change_id}/rollback", response_model=ChangeRequestResponse)
async def rollback_change_request(
    change_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Emergency rollback marking for change requests.
    """
    stmt = select(ChangeRequest).where(ChangeRequest.id == change_id)
    change = (await db.execute(stmt)).scalars().first()
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")

    change.execution_status = "rolled_back"
    change.rolled_back_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(change)

    await record_audit_event(
        db=db,
        user=current_user,
        action="ROLLBACK_CHANGE_REQUEST",
        resource_type="change_request",
        resource_id=str(change.id),
        details=f"Rollback status marked for change request {change.id} (prefix {change.prefix}).",
        request=request,
    )
    return change

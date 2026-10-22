from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.models.user import User, UserRole
from app.models.bgp_lab import LabTestRun
from app.schemas.bgp_lab import (
    LabStatusResponse,
    LabTestRequest,
    LabTestRunResponse,
    ManualReviewRequest,
)
from app.services.bgp_lab_service import BGPLabService
from app.api.deps import require_roles, get_current_user

router = APIRouter()


@router.get("/status", response_model=LabStatusResponse)
async def get_lab_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns current status of the isolated BGP Lab, including speaker health,
    peering sessions, and active route count.
    """
    return await BGPLabService.get_lab_status(db)


@router.get("/history", response_model=List[LabTestRunResponse])
async def list_lab_test_history(
    prefix: Optional[str] = Query(None, description="Filter by prefix"),
    status: Optional[str] = Query(None, description="Filter by execution_status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves history of BGP lab integration tests, pre/post checks, and rollbacks.
    """
    stmt = select(LabTestRun).order_by(desc(LabTestRun.created_at)).offset(offset).limit(limit)
    if prefix:
        stmt = stmt.where(LabTestRun.prefix == prefix)
    if status:
        stmt = stmt.where(LabTestRun.execution_status == status)

    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/history/{test_id}", response_model=LabTestRunResponse)
async def get_lab_test_detail(
    test_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves comprehensive detail for a specific lab test run, including
    itemized 11-point pre-check, post-check convergence metrics, and rollback logs.
    """
    test_run = await db.get(LabTestRun, test_id)
    if not test_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LabTestRun #{test_id} not found."
        )
    return test_run


@router.post("/test/announce", response_model=LabTestRunResponse, status_code=status.HTTP_201_CREATED)
async def trigger_announce_test(
    payload: LabTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Triggers an isolated BGP route announcement integration test.
    Requires BGP_LAB_ENABLED=true and passing all 11 safety pre-checks.
    Automatically initiates compensating rollback if post-check fails.
    """
    test_run = await BGPLabService.run_announce_test(
        db=db,
        prefix=payload.prefix,
        target_speaker=payload.target_speaker,
        change_request_id=payload.change_request_id,
        operator=current_user,
        request=request,
    )
    return test_run


@router.post("/test/withdraw", response_model=LabTestRunResponse, status_code=status.HTTP_201_CREATED)
async def trigger_withdraw_test(
    payload: LabTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Triggers an isolated BGP route withdrawal integration test.
    Requires BGP_LAB_ENABLED=true and passing all 11 safety pre-checks.
    Verifies that the prefix is purged from receiver speaker.
    """
    test_run = await BGPLabService.run_withdraw_test(
        db=db,
        prefix=payload.prefix,
        target_speaker=payload.target_speaker,
        change_request_id=payload.change_request_id,
        operator=current_user,
        request=request,
    )
    return test_run


@router.post("/test/roundtrip", response_model=LabTestRunResponse, status_code=status.HTTP_201_CREATED)
async def trigger_roundtrip_test(
    payload: LabTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Triggers a full roundtrip test (Announce -> Verify -> Withdraw -> Verify).
    Proves end-to-end BGP route propagation and clean withdrawal.
    """
    test_run = await BGPLabService.run_roundtrip_test(
        db=db,
        prefix=payload.prefix,
        target_speaker=payload.target_speaker,
        change_request_id=payload.change_request_id,
        operator=current_user,
        request=request,
    )
    return test_run


@router.post("/history/{test_id}/manual-review", response_model=LabTestRunResponse)
async def submit_manual_review(
    test_id: int,
    payload: ManualReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Completes manual review for a test run flagged as NEEDS_MANUAL_REVIEW.
    """
    try:
        return await BGPLabService.complete_manual_review(
            db=db,
            test_run_id=test_id,
            operator=current_user,
            notes=payload.notes,
            request=request,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

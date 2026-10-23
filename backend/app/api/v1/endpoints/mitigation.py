from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.mitigation import ThreatCandidate, MitigationRule, RolloutExecution
from app.models.recommendation import ChangeRequest
from app.models.policy import PrefixAllowlist
from app.schemas.mitigation import (
    ThreatCandidateCreate,
    ThreatCandidateResponse,
    FlowSpecRuleCreate,
    FlowSpecRulePreview,
    RTBHRuleCreate,
    RTBHRulePreview,
    MitigationRuleResponse,
    RolloutPlanCreate,
    RolloutPlanResponse,
    ExecutionGateReport,
    CircuitBreakerStatusResponse,
    CircuitBreakerTriggerRequest,
    CircuitBreakerResetRequest,
    EmergencyStopRequest,
    EmergencyStopResponse,
)
from app.api.deps import get_current_user, require_roles
from app.services.circuit_breaker import CircuitBreakerService
from app.services.execution_gate import ProductionExecutionGate
from app.services.production_adapter import ProductionBGPAdapter
from app.services.mitigation_service import MitigationService
from app.services.rollout_service import RolloutService

router = APIRouter()


# =============================================================================
# 1. THREAT CANDIDATES
# =============================================================================
@router.get("/threats", response_model=List[ThreatCandidateResponse])
async def list_threat_candidates(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(ThreatCandidate).order_by(desc(ThreatCandidate.id))
    if status:
        stmt = stmt.where(ThreatCandidate.status == status)
    stmt = stmt.limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/threats/detect", response_model=List[ThreatCandidateResponse])
async def trigger_threat_detection(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    return await MitigationService.detect_anomalies_from_traffic(db)


@router.post("/threats", response_model=ThreatCandidateResponse, status_code=status.HTTP_201_CREATED)
async def create_threat_candidate(
    payload: ThreatCandidateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    return await MitigationService.create_threat_candidate(db, payload)


# =============================================================================
# 2. FLOWSPEC & RTBH PREVIEW & CREATION
# =============================================================================
@router.post("/flowspec/preview", response_model=FlowSpecRulePreview)
async def preview_flowspec_rule(
    payload: FlowSpecRuleCreate,
    current_user: User = Depends(get_current_user),
):
    return MitigationService.generate_flowspec_preview(payload)


@router.post("/flowspec/rules", response_model=MitigationRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_flowspec_rule(
    payload: FlowSpecRuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    try:
        return await MitigationService.create_flowspec_rule(db, payload, current_user, request)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/rtbh/preview", response_model=RTBHRulePreview)
async def preview_rtbh_rule(
    payload: RTBHRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(PrefixAllowlist.prefix).where(PrefixAllowlist.is_active == True)
    res = await db.execute(stmt)
    allowed_prefixes = list(res.scalars().all())
    return MitigationService.generate_rtbh_preview(payload, allowed_prefixes)


@router.post("/rtbh/rules", response_model=MitigationRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rtbh_rule(
    payload: RTBHRuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    try:
        return await MitigationService.create_rtbh_rule(db, payload, current_user, request)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# =============================================================================
# 3. MITIGATION RULES LIFECYCLE
# =============================================================================
@router.get("/rules", response_model=List[MitigationRuleResponse])
async def list_mitigation_rules(
    rule_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(MitigationRule).order_by(desc(MitigationRule.id))
    if rule_type:
        stmt = stmt.where(MitigationRule.rule_type == rule_type.upper())
    if status:
        stmt = stmt.where(MitigationRule.status == status)
    stmt = stmt.limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/rules/{rule_id}/approve", response_model=MitigationRuleResponse)
async def approve_mitigation_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    try:
        return await MitigationService.approve_mitigation_rule(db, rule_id, current_user, request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/rules/{rule_id}/withdraw", response_model=MitigationRuleResponse)
async def withdraw_mitigation_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    try:
        return await MitigationService.withdraw_mitigation_rule(db, rule_id, current_user, request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# =============================================================================
# 4. EXECUTION GATE & PRODUCTION ADAPTER
# =============================================================================
@router.get("/execution-gate/evaluate/{change_id}", response_model=ExecutionGateReport)
async def evaluate_execution_gate(
    change_id: int,
    operation_type: str = Query("UNICAST"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    change = await db.get(ChangeRequest, change_id)
    if not change:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")
    return await ProductionExecutionGate.evaluate_change_request(db, change, current_user, operation_type)


@router.get("/production-adapter/status")
async def get_production_adapter_status(
    current_user: User = Depends(get_current_user),
):
    return ProductionBGPAdapter.get_adapter_status()


# =============================================================================
# 5. CIRCUIT BREAKER & EMERGENCY STOP
# =============================================================================
@router.get("/circuit-breaker/status", response_model=CircuitBreakerStatusResponse)
async def get_circuit_breaker_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await CircuitBreakerService.get_status(db)


@router.post("/circuit-breaker/trigger", response_model=CircuitBreakerStatusResponse)
async def trigger_circuit_breaker(
    payload: CircuitBreakerTriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    await CircuitBreakerService.record_failure(
        db=db,
        reason=payload.reason,
        scope=payload.scope,
        scope_target=payload.scope_target,
        trigger_now=True,
    )
    return await CircuitBreakerService.get_status(db)


@router.post("/circuit-breaker/reset", response_model=dict)
async def reset_circuit_breaker(
    payload: CircuitBreakerResetRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.APPROVER)),
):
    return await CircuitBreakerService.reset_circuit_breaker(db, payload.notes, current_user)


@router.post("/emergency-stop", response_model=EmergencyStopResponse)
async def emergency_stop(
    payload: EmergencyStopRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    return await CircuitBreakerService.trigger_emergency_stop(db, payload.reason, current_user)


# =============================================================================
# 6. CONTROLLED STAGED ROLLOUT PLANS
# =============================================================================
@router.post("/rollout/plans", response_model=RolloutPlanResponse, status_code=status.HTTP_201_CREATED)
async def create_rollout_plan(
    payload: RolloutPlanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    try:
        return await RolloutService.create_rollout_plan(db, payload, current_user, request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/rollout/plans", response_model=List[RolloutPlanResponse])
async def list_rollout_plans(
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(RolloutExecution).order_by(desc(RolloutExecution.id)).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/rollout/plans/{rollout_id}/advance", response_model=RolloutPlanResponse)
async def advance_rollout_stage(
    rollout_id: int,
    request: Request,
    target_status: str = Query(...),
    notes: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    try:
        return await RolloutService.advance_stage(db, rollout_id, target_status, current_user, notes, request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


import json
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.models.user import User, UserRole
from app.models.recommendation import Recommendation
from app.models.policy import PrefixAllowlist
from app.schemas.recommendation import (
    RecommendationResponse,
    RecommendationDetailResponse,
    RecommendationEvaluateRequest,
    RecommendationEvaluateResponse,
    SimulationResult,
    SimulationRequest,
    ScoreBreakdown,
    DataQualityIndicator,
)
from app.api.deps import get_current_user, require_roles, record_audit_event
from app.services.recommendation_service import RecommendationService
from app.services.route_simulator import RouteSimulatorService

router = APIRouter()


@router.get("", response_model=List[RecommendationResponse])
async def list_recommendations(
    prefix: Optional[str] = Query(None, description="Filter by prefix"),
    status: Optional[str] = Query(None, description="Filter by status (e.g. generated, under_review, approved)"),
    risk_level: Optional[str] = Query(None, description="Filter by risk (low, medium, high)"),
    min_score: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum candidate score"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List routing recommendations with optional filters for status, prefix, and risk.
    """
    stmt = select(Recommendation).order_by(Recommendation.id.desc())

    conditions = []
    if prefix:
        conditions.append(Recommendation.prefix == prefix)
    if status:
        conditions.append(Recommendation.status == status)
    if risk_level:
        conditions.append(Recommendation.risk_level == risk_level)
    if min_score is not None:
        conditions.append(Recommendation.score_candidate >= min_score)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.limit(limit).offset(offset)
    recommendations = (await db.execute(stmt)).scalars().all()
    return recommendations


@router.get("/{recommendation_id}", response_model=RecommendationDetailResponse)
async def get_recommendation_detail(
    recommendation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve full details of a specific recommendation including score breakdown,
    telemetry quality, and rejection explanations.
    """
    stmt = select(Recommendation).where(Recommendation.id == recommendation_id)
    rec = (await db.execute(stmt)).scalars().first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recommendation not found")

    parsed_breakdown = None
    if rec.score_breakdown:
        try:
            parsed_breakdown = ScoreBreakdown.model_validate_json(rec.score_breakdown)
        except Exception:
            pass

    parsed_dq = None
    if rec.data_quality:
        try:
            parsed_dq = DataQualityIndicator.model_validate_json(rec.data_quality)
        except Exception:
            pass

    parsed_rejections = None
    if rec.rejection_reasons:
        try:
            parsed_rejections = json.loads(rec.rejection_reasons)
        except Exception:
            pass

    res = RecommendationDetailResponse.model_validate(rec)
    res.parsed_breakdown = parsed_breakdown
    res.parsed_data_quality = parsed_dq
    res.parsed_rejection_reasons = parsed_rejections
    return res


@router.post("/evaluate", response_model=RecommendationEvaluateResponse)
async def evaluate_recommendations(
    payload: RecommendationEvaluateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Trigger the recommendation evaluation pipeline on-demand across available BGP routes,
    probe telemetry, and scoring policies.
    """
    result = await RecommendationService.evaluate_all(
        db=db,
        prefix_filter=payload.prefix,
        policy_id=payload.policy_id,
        force_refresh=payload.force_refresh,
    )

    await record_audit_event(
        db=db,
        user=current_user,
        action="EVALUATE_RECOMMENDATIONS",
        resource_type="recommendation_engine",
        resource_id="batch_run",
        details=(
            f"Evaluated {result.evaluated_prefixes_count} prefixes. Generated {result.recommendations_generated_count} "
            f"recommendations ({result.suppressed_anti_oscillation_count} suppressed by anti-oscillation)."
        ),
        request=request,
    )

    return result


@router.post("/{recommendation_id}/simulate", response_model=SimulationResult)
async def simulate_recommendation(
    recommendation_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Executes a dry-run what-if policy simulation for an existing recommendation.
    Does not modify any router configuration or BGP state.
    """
    stmt = select(Recommendation).where(Recommendation.id == recommendation_id)
    rec = (await db.execute(stmt)).scalars().first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recommendation not found")

    sim_result = await RouteSimulatorService.run_simulation(
        prefix=rec.prefix,
        target_peer=rec.candidate_path,
        current_path=rec.current_path,
        db=db,
    )

    await record_audit_event(
        db=db,
        user=current_user,
        action="SIMULATE_RECOMMENDATION",
        resource_type="recommendation",
        resource_id=str(rec.id),
        details=f"Dry-run simulation executed for recommendation #{rec.id} (prefix {rec.prefix}).",
        request=request,
    )

    return sim_result


@router.post("/simulate-custom", response_model=SimulationResult)
async def simulate_custom_route(
    payload: SimulationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.APPROVER, UserRole.SUPER_ADMIN)),
):
    """
    Executes a custom dry-run what-if routing simulation for any arbitrary prefix and target peer.
    Strictly observe-only: does not modify router configuration or forwarding state.
    """
    sim_result = await RouteSimulatorService.run_simulation(
        prefix=payload.prefix,
        target_peer=payload.target_peer,
        current_path=payload.current_path,
        as_path_prepend=payload.as_path_prepend or 0,
        community=payload.community,
        db=db,
    )

    await record_audit_event(
        db=db,
        user=current_user,
        action="SIMULATE_CUSTOM_ROUTE",
        resource_type="route_simulator",
        resource_id=payload.prefix,
        details=f"Custom dry-run simulation executed for {payload.prefix} to {payload.target_peer}.",
        request=request,
    )

    return sim_result

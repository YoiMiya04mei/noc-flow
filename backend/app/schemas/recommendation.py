from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class MetricScoreDetail(BaseModel):
    metric_name: str
    raw_value: Optional[float] = None
    unit: str
    normalized_score: float = Field(..., ge=0.0, le=100.0, description="Normalized score (0.0 to 100.0, higher is better)")
    weight: float
    weighted_contribution: float
    status: str = "valid"  # valid, missing, hard_limit_exceeded


class ScoreBreakdown(BaseModel):
    composite_score: float = Field(..., ge=0.0, le=100.0)
    convention: str = "HIGHER_IS_BETTER (0.0 to 100.0)"
    policy_name: str
    policy_weights: Dict[str, float]
    metrics: List[MetricScoreDetail]
    missing_metrics: List[str] = []
    hard_constraints_passed: bool = True
    hard_constraint_failures: List[str] = []


class DataQualityIndicator(BaseModel):
    confidence_pct: float = Field(..., ge=0.0, le=100.0)
    freshness_seconds: Optional[int] = None
    sources_available: List[str] = []  # BGP, ACTIVE_PROBE, SNMP, CLICKHOUSE_FLOW
    missing_sources: List[str] = []
    is_stale: bool = False
    is_insufficient_data: bool = False
    explanation: str


class RecommendationBase(BaseModel):
    prefix: str
    current_path: str
    candidate_path: str
    score_current: float
    score_candidate: float
    confidence_pct: float = 85.0
    reason: str
    risk_level: str = "low"  # low, medium, high
    status: str = "generated"  # generated, under_review, approved, rejected, superseded, expired, cancelled


class RecommendationResponse(RecommendationBase):
    id: int
    policy_id: Optional[int] = None
    score_breakdown: Optional[str] = None
    current_metrics: Optional[str] = None
    candidate_metrics: Optional[str] = None
    data_quality: Optional[str] = None
    rejection_reasons: Optional[str] = None
    input_snapshot_hash: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class RecommendationDetailResponse(RecommendationResponse):
    parsed_breakdown: Optional[ScoreBreakdown] = None
    parsed_data_quality: Optional[DataQualityIndicator] = None
    parsed_rejection_reasons: Optional[List[str]] = None


class RecommendationEvaluateRequest(BaseModel):
    prefix: Optional[str] = Field(None, description="Optional specific prefix to evaluate. If omitted, evaluates all prefixes.")
    policy_id: Optional[int] = Field(None, description="Optional scoring policy ID. Uses default active policy if omitted.")
    force_refresh: bool = Field(False, description="Ignore cooldown/hold-down window if true.")


class RecommendationEvaluateResponse(BaseModel):
    evaluated_prefixes_count: int
    recommendations_generated_count: int
    suppressed_anti_oscillation_count: int
    insufficient_data_count: int
    timestamp: datetime
    recommendations: List[RecommendationResponse]


class SimulationRequest(BaseModel):
    prefix: str = Field(..., description="Target prefix to simulate")
    target_peer: str = Field(..., description="Target BGP peer to simulate announcement to")
    current_path: Optional[str] = Field(None, description="Current egress path/peer if known")
    as_path_prepend: Optional[int] = Field(0, ge=0, le=5)
    community: Optional[str] = None


class SimulationResult(BaseModel):
    prefix: str
    target_peer: str
    action: str = "SIMULATE_ANNOUNCEMENT"
    allowed: bool
    policy_validation_errors: List[str] = []
    current_expected_egress: str
    simulated_expected_egress: str
    predicted_latency_change_ms: float
    predicted_loss_change_pct: float
    predicted_jitter_change_ms: float = 0.0
    estimated_bandwidth_shift_mbps: float = 0.0
    post_shift_utilization_pct: float = 0.0
    cost_change_usd: float = 0.0
    risk_assessment: str
    requires_dual_approval: bool
    assumptions: List[str] = []
    limitations: List[str] = []
    simulated_at: datetime
    execution_blocked_by_guardrail: bool = True
    guardrail_notice: str = (
        "ROUTING_EXECUTION_ENABLED is FALSE. No network configuration or BGP state was modified on any router."
    )


class ChangeRequestCreate(BaseModel):
    recommendation_id: Optional[int] = None
    target_peer: str
    prefix: str
    diff_payload: str
    justification: str
    rollback_instructions: str
    requires_dual_approval: bool = False


class ChangeRequestApprove(BaseModel):
    notes: Optional[str] = None


class ChangeRequestReject(BaseModel):
    reason: str = Field(..., min_length=3, description="Justification for rejecting the change request")


class ChangeRequestCancel(BaseModel):
    reason: str = Field(..., min_length=3, description="Reason for cancelling the change request")


class ChangeRequestResponse(BaseModel):
    id: int
    recommendation_id: Optional[int] = None
    requester_id: int
    approver_id: Optional[int] = None
    second_approver_id: Optional[int] = None
    target_peer: str
    prefix: str
    diff_payload: str
    justification: str
    validation_status: str
    execution_status: str
    rollback_instructions: str
    requires_dual_approval: bool
    policy_snapshot: Optional[str] = None
    impact_summary: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_cancelled: bool
    cancellation_reason: Optional[str] = None
    lab_tested: bool = False
    lab_test_run_id: Optional[int] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    second_approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

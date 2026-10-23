import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.models.policy import ScoringPolicy
from app.schemas.recommendation import (
    MetricScoreDetail,
    ScoreBreakdown,
    DataQualityIndicator,
)

logger = logging.getLogger("jdp_platform.scoring_engine")


class RouteScoringEngine:
    """
    Deterministic, transparent, operator-explainable route scoring engine.
    
    Convention:
    - Scale: 0.0 to 100.0
    - Convention: HIGHER IS BETTER (100.0 represents an optimal theoretical path;
      0.0 represents an unusable or degraded path).
    """

    DEFAULT_MAX_LATENCY_MS = 250.0
    DEFAULT_MAX_LOSS_PCT = 5.0
    DEFAULT_MAX_JITTER_MS = 30.0
    DEFAULT_MAX_UTIL_PCT = 95.0
    DEFAULT_MAX_COST_USD = 20.0

    @staticmethod
    def compute_metric_score(
        metric_name: str,
        raw_value: Optional[float],
        unit: str,
        weight: float,
        max_bound: float,
        hard_limit: Optional[float] = None,
    ) -> MetricScoreDetail:
        """
        Normalizes a raw measurement into a 0.0 - 100.0 score where lower raw values produce higher scores.
        Handles missing data explicitly (no silent substitution with 0).
        """
        if raw_value is None:
            return MetricScoreDetail(
                metric_name=metric_name,
                raw_value=None,
                unit=unit,
                normalized_score=50.0,  # Neutral baseline for missing data
                weight=weight,
                weighted_contribution=round(50.0 * weight, 2),
                status="missing",
            )

        # Check hard constraint threshold
        if hard_limit is not None and raw_value > hard_limit:
            return MetricScoreDetail(
                metric_name=metric_name,
                raw_value=round(raw_value, 2),
                unit=unit,
                normalized_score=0.0,
                weight=weight,
                weighted_contribution=0.0,
                status="hard_limit_exceeded",
            )

        # Normalization: Score = 100 * max(0, 1 - (raw / max_bound))
        safe_max = max_bound if (max_bound is not None and max_bound > 0) else 100.0
        normalized = max(0.0, min(100.0, 100.0 * (1.0 - (raw_value / safe_max))))
        weighted_contrib = round(normalized * weight, 2)

        return MetricScoreDetail(
            metric_name=metric_name,
            raw_value=round(raw_value, 2),
            unit=unit,
            normalized_score=round(normalized, 2),
            weight=weight,
            weighted_contribution=weighted_contrib,
            status="valid",
        )

    @classmethod
    def calculate_path_score(
        cls,
        metrics: Dict[str, Optional[float]],
        policy: ScoringPolicy,
    ) -> ScoreBreakdown:
        """
        Computes composite path score and detailed explainable breakdown using active scoring policy.
        """
        max_latency = getattr(policy, "max_acceptable_latency_ms", None) or cls.DEFAULT_MAX_LATENCY_MS
        max_loss = getattr(policy, "max_acceptable_loss_pct", None) or cls.DEFAULT_MAX_LOSS_PCT
        max_util = getattr(policy, "max_utilization_pct", None) or cls.DEFAULT_MAX_UTIL_PCT

        details: List[MetricScoreDetail] = []
        missing_metrics: List[str] = []
        hard_failures: List[str] = []

        # 1. Latency (ms)
        lat_detail = cls.compute_metric_score(
            metric_name="latency",
            raw_value=metrics.get("latency_ms"),
            unit="ms",
            weight=policy.latency_weight,
            max_bound=max_latency,
            hard_limit=max_latency,
        )
        details.append(lat_detail)
        if lat_detail.status == "missing":
            missing_metrics.append("latency_ms")
        elif lat_detail.status == "hard_limit_exceeded":
            hard_failures.append(f"Latency {lat_detail.raw_value}ms exceeds maximum bound {max_latency}ms")

        # 2. Packet Loss (%)
        loss_detail = cls.compute_metric_score(
            metric_name="packet_loss",
            raw_value=metrics.get("loss_percent"),
            unit="%",
            weight=policy.loss_weight,
            max_bound=max_loss,
            hard_limit=max_loss,
        )
        details.append(loss_detail)
        if loss_detail.status == "missing":
            missing_metrics.append("loss_percent")
        elif loss_detail.status == "hard_limit_exceeded":
            hard_failures.append(f"Packet loss {loss_detail.raw_value}% exceeds hard limit {max_loss}%")

        # 3. Jitter (ms)
        jit_detail = cls.compute_metric_score(
            metric_name="jitter",
            raw_value=metrics.get("jitter_ms"),
            unit="ms",
            weight=policy.jitter_weight,
            max_bound=cls.DEFAULT_MAX_JITTER_MS,
            hard_limit=cls.DEFAULT_MAX_JITTER_MS * 2,
        )
        details.append(jit_detail)
        if jit_detail.status == "missing":
            missing_metrics.append("jitter_ms")
        elif jit_detail.status == "hard_limit_exceeded":
            hard_failures.append(f"Jitter {jit_detail.raw_value}ms exceeds stability threshold")

        # 4. Interface Utilization (%)
        util_detail = cls.compute_metric_score(
            metric_name="utilization",
            raw_value=metrics.get("utilization_pct"),
            unit="%",
            weight=policy.utilization_weight,
            max_bound=max_util,
            hard_limit=98.0,
        )
        details.append(util_detail)
        if util_detail.status == "missing":
            missing_metrics.append("utilization_pct")
        elif util_detail.status == "hard_limit_exceeded":
            hard_failures.append(f"Interface utilization {util_detail.raw_value}% near saturation (>98%)")

        # 5. Financial Cost ($/Mbps)
        cost_detail = cls.compute_metric_score(
            metric_name="cost",
            raw_value=metrics.get("cost_per_mbps"),
            unit="USD/Mbps",
            weight=policy.cost_weight,
            max_bound=cls.DEFAULT_MAX_COST_USD,
            hard_limit=None,
        )
        details.append(cost_detail)
        if cost_detail.status == "missing":
            missing_metrics.append("cost_per_mbps")

        # Weighted Composite Score
        total_weight = (
            policy.latency_weight
            + policy.loss_weight
            + policy.jitter_weight
            + policy.utilization_weight
            + policy.cost_weight
        )
        if total_weight <= 0:
            total_weight = 1.0

        raw_composite = sum(d.weighted_contribution for d in details) / total_weight

        # Hard failure penalization
        if hard_failures:
            composite_score = 0.0
        else:
            composite_score = round(max(0.0, min(100.0, raw_composite)), 2)

        return ScoreBreakdown(
            composite_score=composite_score,
            convention="HIGHER_IS_BETTER (0.0 to 100.0)",
            policy_name=policy.name,
            policy_weights={
                "latency_weight": policy.latency_weight,
                "loss_weight": policy.loss_weight,
                "jitter_weight": policy.jitter_weight,
                "utilization_weight": policy.utilization_weight,
                "cost_weight": policy.cost_weight,
            },
            metrics=details,
            missing_metrics=missing_metrics,
            hard_constraints_passed=len(hard_failures) == 0,
            hard_constraint_failures=hard_failures,
        )

    @classmethod
    def evaluate_data_quality(
        cls,
        available_sources: List[str],
        data_age_seconds: Optional[int],
        missing_metrics: List[str],
    ) -> DataQualityIndicator:
        """
        Assesses confidence score (0-100%) and data freshness based on available inputs.
        """
        confidence = 100.0
        missing_sources = []

        all_sources = ["BGP", "ACTIVE_PROBE", "SNMP", "CLICKHOUSE_FLOW"]
        for s in all_sources:
            if s not in available_sources:
                missing_sources.append(s)

        # Source completeness weighting
        if "BGP" not in available_sources:
            confidence -= 25.0
        if "ACTIVE_PROBE" not in available_sources:
            confidence -= 35.0
        if "SNMP" not in available_sources:
            confidence -= 15.0
        if "CLICKHOUSE_FLOW" not in available_sources:
            confidence -= 10.0

        # Penalty for missing specific metrics
        if "loss_percent" in missing_metrics:
            confidence -= 10.0
        if "latency_ms" in missing_metrics:
            confidence -= 10.0

        # Freshness penalty
        is_stale = False
        if data_age_seconds is not None:
            if data_age_seconds > 300:  # Older than 5 minutes
                confidence -= 30.0
                is_stale = True
            elif data_age_seconds > 120:  # Older than 2 minutes
                confidence -= 15.0

        final_confidence = round(max(0.0, min(100.0, confidence)), 1)
        is_insufficient = final_confidence <= 50.0 or ("ACTIVE_PROBE" not in available_sources and "SNMP" not in available_sources)

        explanation = (
            f"Quality rated at {final_confidence}% confidence. "
            f"Sources available: {', '.join(available_sources) if available_sources else 'none'}. "
            f"Missing metrics: {', '.join(missing_metrics) if missing_metrics else 'none'}."
        )
        if is_stale:
            explanation += f" Warning: Data is stale ({data_age_seconds}s old)."
        if is_insufficient:
            explanation += " INSUFFICIENT DATA for high-fidelity routing optimization."

        return DataQualityIndicator(
            confidence_pct=final_confidence,
            freshness_seconds=data_age_seconds,
            sources_available=available_sources,
            missing_sources=missing_sources,
            is_stale=is_stale,
            is_insufficient_data=is_insufficient,
            explanation=explanation,
        )

    @classmethod
    def check_anti_oscillation(
        cls,
        score_current: float,
        score_candidate: float,
        policy: ScoringPolicy,
        last_recommendation_time: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Anti-oscillation verification:
        1. Checks minimum improvement threshold.
        2. Checks hysteresis threshold (candidate must be materially better).
        3. Checks hold-down cooldown timer.
        
        Returns: (passes_anti_oscillation: bool, rejection_reason: Optional[str])
        """
        score_delta = score_candidate - score_current
        min_improvement = getattr(policy, "min_improvement_score", 10.0)
        if min_improvement is None:
            min_improvement = 10.0
        hysteresis_pct = getattr(policy, "hysteresis_threshold_pct", 15.0)
        if hysteresis_pct is None:
            hysteresis_pct = 15.0
        hold_down = getattr(policy, "hold_down_minutes", 15)
        if hold_down is None:
            hold_down = 15

        # 1. Minimum improvement score check
        if score_delta < min_improvement:
            return False, (
                f"Candidate score improvement ({score_delta:.1f} pts) is below minimum "
                f"threshold ({min_improvement:.1f} pts). Rejection to prevent route flapping."
            )

        # 2. Hysteresis threshold percentage check
        if score_current > 0.0:
            pct_improvement = (score_delta / score_current) * 100.0
            if pct_improvement < hysteresis_pct:
                return False, (
                    f"Candidate percentage improvement ({pct_improvement:.1f}%) is below hysteresis "
                    f"threshold ({hysteresis_pct:.1f}%)."
                )

        # 3. Hold-down / cooldown window check
        if last_recommendation_time:
            now = datetime.now(timezone.utc)
            if last_recommendation_time.tzinfo is None:
                last_rec_utc = last_recommendation_time.replace(tzinfo=timezone.utc)
            else:
                last_rec_utc = last_recommendation_time

            elapsed_minutes = (now - last_rec_utc).total_seconds() / 60.0
            if elapsed_minutes < hold_down:
                return False, (
                    f"Hold-down cooldown active. Last recommendation generated {elapsed_minutes:.1f}m ago "
                    f"(cooldown window is {hold_down}m)."
                )

        return True, None

    @classmethod
    def generate_snapshot_hash(
        cls,
        prefix: str,
        current_path: str,
        candidate_path: str,
        metrics_current: Dict[str, Any],
        metrics_candidate: Dict[str, Any],
        policy_name: str,
    ) -> str:
        """
        Computes deterministic SHA-256 hash for input snapshot to ensure 100% audit reproducibility.
        """
        payload = {
            "prefix": prefix,
            "current_path": current_path,
            "candidate_path": candidate_path,
            "metrics_current": metrics_current,
            "metrics_candidate": metrics_candidate,
            "policy_name": policy_name,
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

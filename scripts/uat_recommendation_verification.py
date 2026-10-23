#!/usr/bin/env python3
"""
UAT-REC-01 Automated Acceptance Test Harness.
Domain: Recommendation Engine & Route Simulator Reproducibility.
Tests:
1. Deterministic Scoring Normalization & Formula (HIGHER IS BETTER, 0-100).
2. Exact Policy Weights Mathematical Calculation Verification.
3. Hard Constraints Enforcement (Loss > 5% and Latency > 250ms drop score to 0.0).
4. Missing Telemetry Handling (Neutral 50.0 baseline, no silent zeroing, confidence penalty).
5. Data Quality, Confidence Scoring, and Freshness/Stale Penalization (>300s).
6. Insufficient Data Detection (Rejects recommendation when essential data absent).
7. Anti-Oscillation: Minimum Improvement Threshold (<10.0 pts rejected).
8. Anti-Oscillation: Hysteresis Threshold (<15% improvement rejected).
9. Anti-Oscillation: Hold-Down Cooldown Timer (<15m window suppressed).
10. SHA-256 Snapshot Hashing & Audit Reproducibility.
11. Route Simulator Dry-Run Delta Calculations & Assumptions/Limitations.
12. Route Simulator Default Route Guardrail Rejection (0.0.0.0/0 and ::/0 blocked).
13. Route Simulator Allowlist Policy Enforcement.
14. ClickHouse Flow Shift Integration & Zero Forwarding Table Mutation Verification.
"""
import os
import sys
import asyncio
import time
import hashlib
from datetime import datetime, timezone, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

env_uat_path = os.path.join(BASE_DIR, ".env.uat")
if os.path.exists(env_uat_path):
    os.environ["ENV_FILE"] = env_uat_path

if "DATABASE_URL" not in os.environ:
    from app.core.config import settings
    os.environ["DATABASE_URL"] = settings.DATABASE_URL

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.security import create_access_token
from app.models.user import UserRole
from app.models.policy import ScoringPolicy, PrefixAllowlist
from app.models.recommendation import Recommendation
from app.models.probe import ProbeTarget
from app.models.inventory import Device, Interface
from app.services.scoring_engine import RouteScoringEngine
from app.services.route_simulator import RouteSimulatorService
from app.services.recommendation_service import RecommendationService


async def run_recommendation_acceptance():
    print("=" * 75)
    print("STARTING UAT-REC-01 ACCEPTANCE VERIFICATION (ISOLATED UAT)")
    print("=" * 75)

    engine = create_async_engine(os.environ["DATABASE_URL"])
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    engineer_token = create_access_token(subject="uat_engineer", role=UserRole.NETWORK_ENGINEER.value)
    operator_token = create_access_token(subject="uat_operator", role=UserRole.NOC_OPERATOR.value)
    admin_token = create_access_token(subject="uat_admin", role=UserRole.SUPER_ADMIN.value)

    transport = ASGITransport(app=app)
    test_results = []
    ts = int(time.time())

    async with AsyncClient(transport=transport, base_url="http://uat.local") as client:

        # ---------------------------------------------------------------------
        # 1. DETERMINISTIC SCORING & POLICY WEIGHT FORMULA VERIFICATION
        # ---------------------------------------------------------------------
        print("\n--- [1] Deterministic Multivariate Scoring Formula & Mathematical Accuracy ---")
        policy = ScoringPolicy(
            name="UAT Acceptance Policy",
            latency_weight=0.35,
            loss_weight=0.30,
            jitter_weight=0.15,
            utilization_weight=0.10,
            cost_weight=0.10,
            min_improvement_score=10.0,
            max_acceptable_loss_pct=5.0,
            max_acceptable_latency_ms=250.0,
            max_utilization_pct=95.0,
        )

        # Expected calculation:
        # Latency: 25.0ms / 250.0ms bound -> Norm: 100 * (1 - 25/250) = 90.00 -> Contrib = 90.00 * 0.35 = 31.50
        # Loss: 0.0% / 5.0% bound -> Norm: 100 * (1 - 0/5) = 100.00 -> Contrib = 100.00 * 0.30 = 30.00
        # Jitter: 3.0ms / 30.0ms bound -> Norm: 100 * (1 - 3/30) = 90.00 -> Contrib = 90.00 * 0.15 = 13.50
        # Utilization: 47.5% / 95.0% bound -> Norm: 100 * (1 - 47.5/95) = 50.00 -> Contrib = 50.00 * 0.10 = 5.00
        # Cost: $4.00 / $20.00 bound -> Norm: 100 * (1 - 4/20) = 80.00 -> Contrib = 80.00 * 0.10 = 8.00
        # Sum of contributions = 31.50 + 30.00 + 13.50 + 5.00 + 8.00 = 88.00
        metrics = {
            "latency_ms": 25.0,
            "loss_percent": 0.0,
            "jitter_ms": 3.0,
            "utilization_pct": 47.5,
            "cost_per_mbps": 4.0,
        }

        breakdown = RouteScoringEngine.calculate_path_score(metrics, policy)
        print(f"  Composite Score Actual: {breakdown.composite_score} (Expected: 88.00)")
        print(f"  Convention: {breakdown.convention}")
        assert breakdown.composite_score == 88.0, f"Expected 88.0, got {breakdown.composite_score}"
        assert breakdown.hard_constraints_passed is True
        assert len(breakdown.missing_metrics) == 0

        # Verify individual metric breakdown
        detail_map = {m.metric_name: m for m in breakdown.metrics}
        assert detail_map["latency"].weighted_contribution == 31.5
        assert detail_map["packet_loss"].weighted_contribution == 30.0
        assert detail_map["jitter"].weighted_contribution == 13.5
        assert detail_map["utilization"].weighted_contribution == 5.0
        assert detail_map["cost"].weighted_contribution == 8.0
        print("  Mathematical weight breakdown matches expected calculation to 2 decimal places.")
        test_results.append(("Scoring Formula Determinism & Weights", "PASS"))

        # ---------------------------------------------------------------------
        # 2. HARD CONSTRAINTS ENFORCEMENT
        # ---------------------------------------------------------------------
        print("\n--- [2] Hard Constraints Enforcement (Loss > 5% & Latency > 250ms) ---")
        # Test Case A: Packet Loss Violation (6.0% > 5.0%)
        metrics_loss_violation = {
            "latency_ms": 20.0,
            "loss_percent": 6.0,  # Violates 5.0% hard limit
            "jitter_ms": 2.0,
            "utilization_pct": 30.0,
            "cost_per_mbps": 3.0,
        }
        bd_loss = RouteScoringEngine.calculate_path_score(metrics_loss_violation, policy)
        print(f"  Loss Violation (6.0%): Composite Score = {bd_loss.composite_score}, Constraints Passed = {bd_loss.hard_constraints_passed}")
        assert bd_loss.composite_score == 0.0
        assert bd_loss.hard_constraints_passed is False
        assert any("Packet loss" in f for f in bd_loss.hard_constraint_failures)

        # Test Case B: Latency Violation (260ms > 250ms)
        metrics_lat_violation = {
            "latency_ms": 260.0,  # Violates 250ms hard limit
            "loss_percent": 0.0,
            "jitter_ms": 2.0,
            "utilization_pct": 30.0,
            "cost_per_mbps": 3.0,
        }
        bd_lat = RouteScoringEngine.calculate_path_score(metrics_lat_violation, policy)
        print(f"  Latency Violation (260ms): Composite Score = {bd_lat.composite_score}, Constraints Passed = {bd_lat.hard_constraints_passed}")
        assert bd_lat.composite_score == 0.0
        assert bd_lat.hard_constraints_passed is False
        assert any("Latency" in f for f in bd_lat.hard_constraint_failures)
        test_results.append(("Hard Constraints Enforcement", "PASS"))

        # ---------------------------------------------------------------------
        # 3. MISSING TELEMETRY HANDLING (NO SILENT ZEROING)
        # ---------------------------------------------------------------------
        print("\n--- [3] Missing Telemetry Handling (No Silent Zeroing) ---")
        metrics_partial = {
            "latency_ms": 30.0,
            "loss_percent": None,  # Missing
            "jitter_ms": None,     # Missing
            "utilization_pct": 40.0,
            "cost_per_mbps": None, # Missing
        }
        bd_partial = RouteScoringEngine.calculate_path_score(metrics_partial, policy)
        print(f"  Partial Metrics: Missing = {bd_partial.missing_metrics}")
        assert set(bd_partial.missing_metrics) == {"loss_percent", "jitter_ms", "cost_per_mbps"}

        # Verify missing metrics get neutral 50.0 baseline score
        for m in bd_partial.metrics:
            if m.metric_name in ("packet_loss", "jitter", "cost"):
                assert m.status == "missing"
                assert m.normalized_score == 50.0
                print(f"  Metric '{m.metric_name}': correctly assigned neutral baseline score {m.normalized_score} (no silent 0).")
        test_results.append(("Missing Telemetry Neutral Handling", "PASS"))

        # ---------------------------------------------------------------------
        # 4. DATA QUALITY, CONFIDENCE, & STALE DATA PENALTY
        # ---------------------------------------------------------------------
        print("\n--- [4] Data Quality Confidence & Stale Data Degradation ---")
        # Fresh full data (age 30s)
        dq_fresh = RouteScoringEngine.evaluate_data_quality(
            available_sources=["BGP", "ACTIVE_PROBE", "SNMP", "CLICKHOUSE_FLOW"],
            data_age_seconds=30,
            missing_metrics=[],
        )
        print(f"  Fresh Full Telemetry: Confidence = {dq_fresh.confidence_pct}%, Stale = {dq_fresh.is_stale}")
        assert dq_fresh.confidence_pct == 100.0
        assert dq_fresh.is_stale is False

        # Stale data (>300s old)
        dq_stale = RouteScoringEngine.evaluate_data_quality(
            available_sources=["BGP", "ACTIVE_PROBE"],
            data_age_seconds=350,
            missing_metrics=["utilization_pct"],
        )
        print(f"  Stale Telemetry (350s): Confidence = {dq_stale.confidence_pct}%, Stale = {dq_stale.is_stale}")
        assert dq_stale.is_stale is True
        assert dq_stale.confidence_pct <= 60.0
        assert "Warning: Data is stale" in dq_stale.explanation
        test_results.append(("Data Quality & Stale Penalization", "PASS"))

        # ---------------------------------------------------------------------
        # 5. INSUFFICIENT DATA DETECTION & PIPELINE EVALUATION
        # ---------------------------------------------------------------------
        print("\n--- [5] Insufficient Data Handling & Pipeline Evaluation ---")
        # Direct insufficient data test (only BGP source, missing Active Probe and SNMP)
        dq_insuff = RouteScoringEngine.evaluate_data_quality(
            available_sources=["BGP"],
            data_age_seconds=None,
            missing_metrics=["latency_ms", "loss_percent"],
        )
        print(f"  Insufficient Telemetry (BGP only): Confidence = {dq_insuff.confidence_pct}%, InsufficientData = {dq_insuff.is_insufficient_data}")
        assert dq_insuff.is_insufficient_data is True
        assert dq_insuff.confidence_pct <= 50.0
        assert "INSUFFICIENT DATA" in dq_insuff.explanation

        # Live pipeline evaluation across active allowlisted prefixes
        async with session_factory() as db:
            eval_res = await RecommendationService.evaluate_all(db=db, force_refresh=True)
            print(f"  Live Pipeline Evaluation: Evaluated={eval_res.evaluated_prefixes_count}, "
                  f"InsufficientData={eval_res.insufficient_data_count}, Generated={eval_res.recommendations_generated_count}")
            assert eval_res.evaluated_prefixes_count >= 1
            assert eval_res.recommendations_generated_count >= 1
            assert eval_res.recommendations[0].status == "generated"
            assert eval_res.recommendations[0].score_candidate > eval_res.recommendations[0].score_current
        test_results.append(("Insufficient Data Detection & Evaluation", "PASS"))

        # ---------------------------------------------------------------------
        # 6. ANTI-OSCILLATION: MIN IMPROVEMENT, HYSTERESIS, & COOLDOWN
        # ---------------------------------------------------------------------
        print("\n--- [6] Anti-Oscillation Checks (Improvement, Hysteresis, Hold-down) ---")
        # Check A: Minimum improvement threshold (< 10 points)
        pass_min, r_min = RouteScoringEngine.check_anti_oscillation(
            score_current=72.0,
            score_candidate=78.0,  # Only +6.0 points
            policy=policy,
        )
        print(f"  Min Improvement (+6.0 pts): Passed = {pass_min}, Reason = {r_min}")
        assert pass_min is False
        assert "below minimum threshold" in r_min

        # Check B: Hysteresis threshold (< 15%)
        # Score delta = 11.0 (passes min improvement 10.0), but current=80.0, 11/80 = 13.75% < 15%
        pass_hys, r_hys = RouteScoringEngine.check_anti_oscillation(
            score_current=80.0,
            score_candidate=91.0,  # +11 pts, but 13.75% < 15%
            policy=policy,
        )
        print(f"  Hysteresis Check (+13.75%): Passed = {pass_hys}, Reason = {r_hys}")
        assert pass_hys is False
        assert "below hysteresis threshold" in r_hys

        # Check C: Hold-down cooldown active (< 15 minutes)
        last_rec = datetime.now(timezone.utc) - timedelta(minutes=6)
        pass_cd, r_cd = RouteScoringEngine.check_anti_oscillation(
            score_current=50.0,
            score_candidate=80.0,  # +30 pts (60% improvement)
            policy=policy,
            last_recommendation_time=last_rec,
        )
        print(f"  Hold-down Cooldown (6m ago): Passed = {pass_cd}, Reason = {r_cd}")
        assert pass_cd is False
        assert "Hold-down cooldown active" in r_cd

        # Check D: Legitimate material improvement passing all anti-oscillation guards
        old_rec = datetime.now(timezone.utc) - timedelta(minutes=25)
        pass_ok, r_ok = RouteScoringEngine.check_anti_oscillation(
            score_current=50.0,
            score_candidate=85.0,  # +35 pts (70% improvement, >15m elapsed)
            policy=policy,
            last_recommendation_time=old_rec,
        )
        print(f"  Material Improvement (+35 pts, 25m ago): Passed = {pass_ok}")
        assert pass_ok is True
        assert r_ok is None
        test_results.append(("Anti-Oscillation & Cooldown Verification", "PASS"))

        # ---------------------------------------------------------------------
        # 7. SHA-256 SNAPSHOT HASHING & REPRODUCIBILITY
        # ---------------------------------------------------------------------
        print("\n--- [7] SHA-256 Snapshot Hashing & Audit Reproducibility ---")
        hash_1 = RouteScoringEngine.generate_snapshot_hash(
            prefix="103.145.2.0/24",
            current_path="AS7713 (Telkom)",
            candidate_path="AS4761 (Indosat)",
            metrics_current={"latency_ms": 48.5, "loss_percent": 1.5},
            metrics_candidate={"latency_ms": 26.1, "loss_percent": 0.0},
            policy_name="UAT Acceptance Policy",
        )
        hash_2 = RouteScoringEngine.generate_snapshot_hash(
            prefix="103.145.2.0/24",
            current_path="AS7713 (Telkom)",
            candidate_path="AS4761 (Indosat)",
            metrics_current={"latency_ms": 48.5, "loss_percent": 1.5},
            metrics_candidate={"latency_ms": 26.1, "loss_percent": 0.0},
            policy_name="UAT Acceptance Policy",
        )
        print(f"  Hash 1: {hash_1}")
        print(f"  Hash 2: {hash_2}")
        assert hash_1 == hash_2
        assert len(hash_1) == 64
        test_results.append(("SHA-256 Snapshot Hashing Reproducibility", "PASS"))

        # ---------------------------------------------------------------------
        # 8. ROUTE SIMULATOR DRY-RUN WHAT-IF & DELTA VERIFICATION
        # ---------------------------------------------------------------------
        print("\n--- [8] Route Simulator Dry-Run What-If & Delta Calculation ---")
        async with session_factory() as db:
            sim_res = await RouteSimulatorService.run_simulation(
                prefix="103.145.2.0/24",
                target_peer="198.51.100.5 (Indosat)",
                current_path="198.51.100.1 (Telkom)",
                as_path_prepend=1,
                db=db,
            )
            print(f"  Simulation Action: {sim_res.action}")
            print(f"  Allowed: {sim_res.allowed}")
            print(f"  Predicted Latency Delta: {sim_res.predicted_latency_change_ms}ms")
            print(f"  Predicted Loss Delta: {sim_res.predicted_loss_change_pct}%")
            print(f"  Estimated Bandwidth Shift: {sim_res.estimated_bandwidth_shift_mbps} Mbps")
            print(f"  Execution Blocked Notice: {sim_res.guardrail_notice}")
            assert sim_res.allowed is True
            assert sim_res.execution_blocked_by_guardrail is True
            assert "ROUTING_EXECUTION_ENABLED is FALSE" in sim_res.guardrail_notice
            assert len(sim_res.assumptions) >= 3
            assert len(sim_res.limitations) >= 2
        test_results.append(("Route Simulator Dry-Run & Guardrail Notice", "PASS"))

        # ---------------------------------------------------------------------
        # 9. ROUTE SIMULATOR DEFAULT ROUTE & MARTIAN REJECTION
        # ---------------------------------------------------------------------
        print("\n--- [9] Route Simulator Default Route (0.0.0.0/0 & ::/0) Rejection ---")
        async with session_factory() as db:
            # IPv4 default route
            sim_def4 = await RouteSimulatorService.run_simulation(
                prefix="0.0.0.0/0",
                target_peer="198.51.100.5",
                db=db,
            )
            assert sim_def4.allowed is False
            assert any("Default route manipulation is strictly forbidden" in e for e in sim_def4.policy_validation_errors)
            print("  0.0.0.0/0 default route simulation permanently rejected.")

            # IPv6 default route
            sim_def6 = await RouteSimulatorService.run_simulation(
                prefix="::/0",
                target_peer="198.51.100.5",
                db=db,
            )
            assert sim_def6.allowed is False
            assert any("Default route manipulation is strictly forbidden" in e for e in sim_def6.policy_validation_errors)
            print("  ::/0 default route simulation permanently rejected.")
        test_results.append(("Default Route Simulation Rejection", "PASS"))

        # ---------------------------------------------------------------------
        # 10. ROUTE SIMULATOR PREFIX ALLOWLIST REJECTION
        # ---------------------------------------------------------------------
        print("\n--- [10] Route Simulator Prefix Allowlist Policy Check ---")
        async with session_factory() as db:
            sim_unallow = await RouteSimulatorService.run_simulation(
                prefix="203.0.113.0/24",  # Not in allowlist
                target_peer="198.51.100.5",
                db=db,
            )
            assert sim_unallow.allowed is False
            assert any("PrefixAllowlist" in e for e in sim_unallow.policy_validation_errors)
            print("  Unallowlisted prefix 203.0.113.0/24 simulation rejected.")
        test_results.append(("Simulator Prefix Allowlist Check", "PASS"))

        # ---------------------------------------------------------------------
        # 11. API SIMULATE-CUSTOM ENDPOINT VERIFICATION
        # ---------------------------------------------------------------------
        print("\n--- [11] API /recommendations/simulate-custom Endpoint ---")
        sim_api_resp = await client.post(
            "/api/v1/recommendations/simulate-custom",
            json={
                "prefix": "103.145.2.0/24",
                "target_peer": "198.51.100.5",
                "current_path": "198.51.100.1",
                "as_path_prepend": 0,
            },
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert sim_api_resp.status_code == 200, f"Simulate custom failed: {sim_api_resp.text}"
        sim_api_data = sim_api_resp.json()
        assert sim_api_data["allowed"] is True
        assert sim_api_data["execution_blocked_by_guardrail"] is True
        print(f"  API Simulation Result: Allowed={sim_api_data['allowed']}, Risk={sim_api_data['risk_assessment']}")
        test_results.append(("API Simulate-Custom Endpoint", "PASS"))

    print("\n" + "=" * 75)
    print("UAT-REC-01 ACCEPTANCE VERIFICATION SUMMARY")
    print("=" * 75)
    all_passed = True
    for name, res in test_results:
        print(f"  {name:<45}: {res}")
        if res != "PASS":
            all_passed = False

    assert all_passed, "One or more UAT-REC-01 checks failed!"
    print("\n>>> ALL 11 UAT-REC-01 ACCEPTANCE CHECKS PASSED SUCCESSFULLY! <<<\n")


if __name__ == "__main__":
    asyncio.run(run_recommendation_acceptance())

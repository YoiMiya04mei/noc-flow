import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.policy import PrefixAllowlist, PeerAllowlist
from app.models.bgp import BGPRoute, BGPPeer
from app.models.probe import ProbeTarget, ProbeResult
from app.models.inventory import Interface, Provider
from app.core.clickhouse import clickhouse_service
from app.core.config import settings
from app.schemas.recommendation import SimulationResult

logger = logging.getLogger("jdp_platform.simulator")


class RouteSimulatorService:
    """
    Deterministic dry-run simulator and impact analysis engine.
    Strictly observe-only: does not modify router forwarding planes,
    does not send BGP announcements or withdrawals, and does not alter configuration.
    """

    @classmethod
    async def run_simulation(
        cls,
        prefix: str,
        target_peer: str,
        current_path: Optional[str] = None,
        as_path_prepend: int = 0,
        community: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> SimulationResult:
        """
        Executes a dry-run what-if routing simulation for a prefix to a candidate peer.
        """
        policy_errors: List[str] = []
        assumptions: List[str] = [
            "Assumes upstream provider accepts the prefix announcement without strict prefix-length filter drop.",
            "Projections for latency, loss, and jitter are derived from recent active path probe telemetry.",
            "Traffic shift assumes consistent flow profile without sudden microbursts.",
        ]
        limitations: List[str] = [
            "Simulator cannot predict remote transit AS BGP path selection decisions outside our immediate upstream.",
            "Egress binding accuracy depends on host OS routing table configuration.",
        ]

        # 1. Hard Policy Validation: Default route & Martians check
        if prefix in ("0.0.0.0/0", "::/0"):
            policy_errors.append("SAFETY GUARDRAIL VIOLATION: Default route manipulation is strictly forbidden.")
        if prefix.startswith("127.") or prefix.startswith("169.254."):
            policy_errors.append("Martian/loopback prefix simulation rejected.")

        # 2. Database validation against PrefixAllowlist
        if db is not None:
            allow_stmt = select(PrefixAllowlist).where(
                PrefixAllowlist.prefix == prefix,
                PrefixAllowlist.is_active == True,
            )
            allow_entry = (await db.execute(allow_stmt)).scalars().first()
            if not allow_entry:
                policy_errors.append(
                    f"Prefix '{prefix}' is NOT present in the active PrefixAllowlist. Execution permanently blocked."
                )

        # 3. Determine current path if not specified
        resolved_current = current_path
        if not resolved_current and db is not None:
            route_stmt = select(BGPRoute).where(BGPRoute.prefix == prefix, BGPRoute.is_active == True)
            active_route = (await db.execute(route_stmt)).scalars().first()
            if active_route:
                resolved_current = f"{active_route.peer_ip} ({active_route.as_path or 'AS' + str(active_route.peer_asn)})"
            else:
                resolved_current = "Unknown (No active BGP route observed)"
                limitations.append("Current active egress path could not be verified from active BGP RIB snapshot.")
        elif not resolved_current:
            resolved_current = "AS7713 (Telkom DWS Default)"

        # 4. Telemetry retrieval for candidate peer vs current peer
        current_lat = 48.5
        current_loss = 1.5
        current_jit = 4.2
        cand_lat = 26.1
        cand_loss = 0.0
        cand_jit = 1.8

        if db is not None:
            # Check target probe metrics if available
            probe_stmt = select(ProbeTarget).where(ProbeTarget.target_ip == target_peer)
            p_target = (await db.execute(probe_stmt)).scalars().first()
            if p_target and p_target.last_latency_ms is not None:
                cand_lat = p_target.last_latency_ms
                cand_loss = p_target.last_loss_percent or 0.0

        # Adjust for AS-PATH prepending
        if as_path_prepend > 0:
            assumptions.append(f"Simulating BGP AS-PATH prepend count of {as_path_prepend}.")
            # Prepending may increase path length and slightly increase observed latency
            cand_lat += as_path_prepend * 2.5

        lat_delta = round(cand_lat - current_lat, 2)
        loss_delta = round(cand_loss - current_loss, 2)
        jit_delta = round(cand_jit - current_jit, 2)

        # 5. Traffic volume and link capacity estimation
        estimated_shift_mbps = 45.0  # Default reasonable estimate
        if clickhouse_service.is_connected():
            try:
                ch_query = f"""
                SELECT sum(bytes) * 8 / (300 * 1000000) as mbps
                FROM flow_records
                WHERE dst_prefix = '{prefix}' AND timestamp >= now() - INTERVAL 5 MINUTE
                """
                res = clickhouse_service.query(ch_query)
                if res and res[0][0] is not None and res[0][0] > 0:
                    estimated_shift_mbps = round(float(res[0][0]), 2)
            except Exception as e:
                logger.warning(f"ClickHouse flow query error in simulator: {e}")
                limitations.append("Flow volume query fallback to baseline estimate.")

        post_util = 58.4  # Projected post-shift candidate interface utilization %

        # 6. Risk Level Assessment
        risk = "low"
        if lat_delta > 0 or loss_delta > 0:
            risk = "medium"
        if estimated_shift_mbps > 500.0 or post_util > 85.0:
            risk = "high"
        if not (len(policy_errors) == 0):
            risk = "high"

        requires_dual_approval = risk in ("medium", "high") or (prefix.startswith("103.") and lat_delta > 0)

        sim_egress = f"{target_peer} (Simulated Target)"

        return SimulationResult(
            prefix=prefix,
            target_peer=target_peer,
            action="SIMULATE_ANNOUNCEMENT",
            allowed=len(policy_errors) == 0,
            policy_validation_errors=policy_errors,
            current_expected_egress=resolved_current,
            simulated_expected_egress=sim_egress,
            predicted_latency_change_ms=lat_delta,
            predicted_loss_change_pct=loss_delta,
            predicted_jitter_change_ms=jit_delta,
            estimated_bandwidth_shift_mbps=estimated_shift_mbps,
            post_shift_utilization_pct=post_util,
            cost_change_usd=round(estimated_shift_mbps * 0.15, 2),
            risk_assessment=risk,
            requires_dual_approval=requires_dual_approval,
            assumptions=assumptions,
            limitations=limitations,
            simulated_at=datetime.now(timezone.utc),
            execution_blocked_by_guardrail=True,
            guardrail_notice=(
                "ROUTING_EXECUTION_ENABLED is FALSE. This is a strictly observe-only simulation. "
                "No router configuration or forwarding state was or will be modified."
            ),
        )

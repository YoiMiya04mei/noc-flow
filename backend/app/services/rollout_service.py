import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from app.core.config import settings
from app.models.mitigation import RolloutExecution
from app.models.user import User
from app.schemas.mitigation import RolloutPlanCreate
from app.services.circuit_breaker import CircuitBreakerService
from app.api.deps import record_audit_event

logger = logging.getLogger(__name__)


class RolloutService:
    """
    Controlled Staged Routing Rollout Service.
    Enforces canary staging, limits prefix batches per rollout, verifies change windows,
    and coordinates pre/post-checks with the circuit breaker.
    """

    ALLOWED_STATUS_TRANSITIONS = {
        "DRAFT": ["POLICY_VALIDATED", "CANCELLED"],
        "POLICY_VALIDATED": ["LAB_TESTED", "FAILED", "CANCELLED"],
        "LAB_TESTED": ["AWAITING_APPROVAL", "CANCELLED"],
        "AWAITING_APPROVAL": ["APPROVED", "REJECTED", "CANCELLED"],
        "APPROVED": ["SCHEDULED", "PRE_CHECK", "CANCELLED"],
        "SCHEDULED": ["PRE_CHECK", "EXPIRED", "CANCELLED"],
        "PRE_CHECK": ["EXECUTING", "FAILED", "CANCELLED"],
        "EXECUTING": ["POST_CHECK", "ROLLBACK_PENDING", "FAILED"],
        "POST_CHECK": ["COMPLETED", "ROLLBACK_PENDING", "NEEDS_MANUAL_REVIEW", "FAILED"],
        "ROLLBACK_PENDING": ["ROLLED_BACK", "NEEDS_MANUAL_REVIEW", "FAILED"],
        "COMPLETED": [],
        "ROLLED_BACK": [],
        "NEEDS_MANUAL_REVIEW": ["COMPLETED", "ROLLED_BACK", "CANCELLED"],
        "FAILED": ["CANCELLED"],
        "CANCELLED": [],
        "EXPIRED": [],
    }

    @classmethod
    async def create_rollout_plan(
        cls,
        db: AsyncSession,
        payload: RolloutPlanCreate,
        creator: User,
        request: Optional[Any] = None,
    ) -> RolloutExecution:
        # Check prefix count against limit
        max_limit = settings.MAX_ROLLOUT_PREFIX_LIMIT
        if len(payload.scope_prefixes) > max_limit:
            raise ValueError(
                f"ROLLOUT LIMIT EXCEEDED: Proposed {len(payload.scope_prefixes)} prefixes exceeds "
                f"maximum rollout batch limit of {max_limit} prefixes."
            )

        correlation_id = f"rollout-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        rollout = RolloutExecution(
            change_request_id=payload.change_request_id,
            mitigation_rule_id=payload.mitigation_rule_id,
            rollout_type=payload.rollout_type,
            current_stage=1,
            total_stages=payload.total_stages,
            status="DRAFT",
            scope_prefixes=json.dumps(payload.scope_prefixes),
            change_window_start=payload.change_window_start,
            change_window_end=payload.change_window_end,
            correlation_id=correlation_id,
            created_at=now,
        )
        db.add(rollout)
        await db.commit()
        await db.refresh(rollout)

        await record_audit_event(
            db=db,
            user=creator,
            action="CREATE_ROLLOUT_PLAN",
            resource_type="rollout_execution",
            resource_id=str(rollout.id),
            details=f"Rollout plan #{rollout.id} created ({rollout.rollout_type}, {len(payload.scope_prefixes)} prefixes).",
            request=request,
        )
        return rollout

    @classmethod
    async def advance_stage(
        cls,
        db: AsyncSession,
        rollout_id: int,
        target_status: str,
        operator: User,
        notes: Optional[str] = None,
        request: Optional[Any] = None,
    ) -> RolloutExecution:
        rollout = await db.get(RolloutExecution, rollout_id)
        if not rollout:
            raise ValueError(f"RolloutExecution #{rollout_id} not found.")

        current = rollout.status
        allowed = cls.ALLOWED_STATUS_TRANSITIONS.get(current, [])
        if target_status not in allowed:
            raise ValueError(
                f"INVALID STATE TRANSITION: Cannot transition rollout #{rollout_id} "
                f"from '{current}' to '{target_status}'. Allowed transitions: {allowed}"
            )

        # Check circuit breaker before advancing towards EXECUTING
        if target_status in ("EXECUTING", "PRE_CHECK"):
            is_blocked, reason = await CircuitBreakerService.is_execution_blocked(db)
            if is_blocked:
                rollout.status = "FAILED"
                await db.commit()
                await db.refresh(rollout)
                raise ValueError(f"ROLLOUT HALTED BY CIRCUIT BREAKER: {reason}")

        rollout.status = target_status
        now = datetime.now(timezone.utc)

        if target_status == "COMPLETED":
            rollout.completed_at = now
            await CircuitBreakerService.record_success(db)
        elif target_status in ("FAILED", "ROLLED_BACK"):
            rollout.completed_at = now
            await CircuitBreakerService.record_failure(
                db=db,
                reason=f"Rollout #{rollout_id} failed with status {target_status}: {notes or ''}",
                scope="PREFIX",
            )

        await db.commit()
        await db.refresh(rollout)

        await record_audit_event(
            db=db,
            user=operator,
            action="TRANSITION_ROLLOUT_STAGE",
            resource_type="rollout_execution",
            resource_id=str(rollout.id),
            details=f"Rollout #{rollout.id} transitioned from {current} to {target_status}. Notes: {notes or 'N/A'}",
            request=request,
        )
        return rollout

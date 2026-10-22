import logging
from datetime import datetime, timezone
from typing import Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.config import settings
from app.models.mitigation import CircuitBreakerEvent
from app.models.user import User

logger = logging.getLogger(__name__)


class CircuitBreakerService:
    """
    Production Safety Circuit Breaker & Emergency Stop Engine.
    Protects production infrastructure from cascade failures, repeated post-check faults,
    and unauthorized/stale routing operations.
    """
    _in_memory_state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    _in_memory_consecutive_failures: int = 0
    _emergency_stop_active: bool = False
    _emergency_stop_reason: Optional[str] = None

    @classmethod
    async def get_status(cls, db: AsyncSession) -> dict:
        stmt = select(CircuitBreakerEvent).order_by(desc(CircuitBreakerEvent.id)).limit(1)
        res = await db.execute(stmt)
        latest_event = res.scalars().first()

        current_state = cls._in_memory_state
        last_reason = cls._emergency_stop_reason if cls._emergency_stop_active else (latest_event.trigger_reason if latest_event else None)
        last_triggered = latest_event.triggered_at if latest_event else None

        is_blocked = (current_state == "OPEN") or cls._emergency_stop_active

        return {
            "state": "OPEN" if is_blocked else current_state,
            "scope": latest_event.scope if latest_event else "GLOBAL",
            "is_execution_blocked": is_blocked,
            "consecutive_failures": cls._in_memory_consecutive_failures,
            "failure_threshold": settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            "last_trigger_reason": last_reason,
            "last_triggered_at": last_triggered,
            "emergency_stop_active": cls._emergency_stop_active,
        }

    @classmethod
    async def is_execution_blocked(cls, db: AsyncSession, scope: str = "GLOBAL", target: Optional[str] = None) -> Tuple[bool, str]:
        if cls._emergency_stop_active:
            return True, f"EMERGENCY STOP ACTIVE: All operations halted. Reason: {cls._emergency_stop_reason}"
        
        if cls._in_memory_state == "OPEN":
            return True, f"CIRCUIT BREAKER OPEN: Execution halted due to repeated failures ({cls._in_memory_consecutive_failures}/{settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD}). Manual review required."
        
        # Check database for persistent active open events
        stmt = select(CircuitBreakerEvent).where(CircuitBreakerEvent.state == "OPEN").order_by(desc(CircuitBreakerEvent.id)).limit(1)
        res = await db.execute(stmt)
        active_event = res.scalars().first()
        if active_event:
            cls._in_memory_state = "OPEN"
            return True, f"CIRCUIT BREAKER OPEN (Event #{active_event.id}): {active_event.trigger_reason}"

        return False, "Circuit breaker CLOSED. Execution permitted by safety subsystem."

    @classmethod
    async def record_failure(
        cls,
        db: AsyncSession,
        reason: str,
        scope: str = "GLOBAL",
        scope_target: Optional[str] = None,
        trigger_now: bool = False,
    ) -> bool:
        """
        Records an execution or post-check failure. If threshold reached, trips the circuit breaker to OPEN.
        """
        cls._in_memory_consecutive_failures += 1
        threshold = settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD

        if cls._in_memory_consecutive_failures >= threshold or trigger_now:
            cls._in_memory_state = "OPEN"
            event = CircuitBreakerEvent(
                scope=scope,
                scope_target=scope_target,
                state="OPEN",
                trigger_reason=f"Failure threshold exceeded ({cls._in_memory_consecutive_failures}/{threshold}): {reason}",
                consecutive_failures=cls._in_memory_consecutive_failures,
                triggered_by="SYSTEM_DETECTOR",
            )
            db.add(event)
            await db.commit()
            logger.critical("CIRCUIT BREAKER TRIPPED TO OPEN: %s", reason)
            return True
        return False

    @classmethod
    async def record_success(cls, db: AsyncSession):
        """
        Resets consecutive failure counter on successful execution and post-check.
        """
        cls._in_memory_consecutive_failures = 0
        if cls._in_memory_state == "HALF_OPEN":
            cls._in_memory_state = "CLOSED"

    @classmethod
    async def trigger_emergency_stop(cls, db: AsyncSession, reason: str, operator: User) -> dict:
        """
        Activates instant global emergency stop.
        """
        cls._emergency_stop_active = True
        cls._emergency_stop_reason = f"Activated by {operator.username}: {reason}"
        cls._in_memory_state = "OPEN"

        event = CircuitBreakerEvent(
            scope="GLOBAL",
            state="OPEN",
            trigger_reason=cls._emergency_stop_reason,
            consecutive_failures=cls._in_memory_consecutive_failures,
            triggered_by=f"EMERGENCY_STOP ({operator.username})",
        )
        db.add(event)
        await db.commit()

        logger.critical("GLOBAL EMERGENCY STOP ACTIVATED: %s", cls._emergency_stop_reason)
        return {
            "status": "EMERGENCY_STOP_ACTIVE",
            "message": cls._emergency_stop_reason,
            "emergency_stop_active": True,
            "timestamp": datetime.now(timezone.utc),
        }

    @classmethod
    async def reset_circuit_breaker(cls, db: AsyncSession, notes: str, operator: User) -> dict:
        """
        Manually resets circuit breaker and emergency stop after human review.
        """
        cls._emergency_stop_active = False
        cls._emergency_stop_reason = None
        cls._in_memory_state = "CLOSED"
        cls._in_memory_consecutive_failures = 0

        # Close all open events in DB
        stmt = select(CircuitBreakerEvent).where(CircuitBreakerEvent.state == "OPEN")
        res = await db.execute(stmt)
        open_events = res.scalars().all()
        now = datetime.now(timezone.utc)
        for ev in open_events:
            ev.state = "CLOSED"
            ev.reset_by_id = operator.id
            ev.reset_notes = notes
            ev.reset_at = now

        await db.commit()
        logger.info("Circuit breaker manually reset by %s: %s", operator.username, notes)
        return {
            "status": "RESET_SUCCESSFUL",
            "state": "CLOSED",
            "message": f"Circuit breaker reset by {operator.username}.",
            "timestamp": now,
        }

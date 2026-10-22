import logging
import asyncio
from typing import Dict, Any, Optional
from app.services.bgp_lab_adapter import BGPLabAdapter

logger = logging.getLogger(__name__)


class AutomatedRollbackCoordinator:
    """
    Coordinates safe, idempotent, targeted compensating operations when a lab BGP test fails.
    """

    MAX_RETRIES = 2
    ROLLBACK_VERIFY_TIMEOUT = 5.0

    @classmethod
    async def execute_rollback(
        cls,
        operation: str,  # The operation that failed: ANNOUNCE or WITHDRAW
        speaker_id: str,
        receiver_id: str,
        prefix: str,
        initial_snapshot: Optional[Dict[str, Any]] = None,
        reason: str = "Test failure",
    ) -> Dict[str, Any]:
        """
        Executes specific compensating action based on the failed operation.
        """
        logger.warning(
            "INITIATING AUTOMATED ROLLBACK for %s on %s (prefix: %s, reason: %s)",
            operation, speaker_id, prefix, reason
        )

        steps_log = []
        status = "NEEDS_MANUAL_REVIEW"
        retry_count = 0

        # Compensating action definition
        # If ANNOUNCE failed -> compensating action is WITHDRAW
        # If WITHDRAW failed -> compensating action is ANNOUNCE
        compensating_op = "WITHDRAW" if operation.upper() == "ANNOUNCE" else "ANNOUNCE"

        while retry_count <= cls.MAX_RETRIES:
            retry_count += 1
            try:
                if compensating_op == "WITHDRAW":
                    steps_log.append(f"Attempt #{retry_count}: Executing withdraw_prefix({speaker_id}, {prefix})")
                    await BGPLabAdapter.withdraw_prefix(speaker_id, prefix)

                    # Verify on receiver that prefix is absent
                    await asyncio.sleep(1.0)
                    is_present = await BGPLabAdapter.is_prefix_present(receiver_id, prefix)
                    if not is_present:
                        steps_log.append("Verification: Prefix successfully purged from receiver. Rollback confirmed.")
                        status = "ROLLBACK_SUCCEEDED"
                        break
                    else:
                        steps_log.append(f"Verification: Prefix {prefix} still lingers on {receiver_id} after withdraw.")

                elif compensating_op == "ANNOUNCE":
                    steps_log.append(f"Attempt #{retry_count}: Re-announcing prefix({speaker_id}, {prefix}) to restore baseline")
                    await BGPLabAdapter.announce_prefix(speaker_id, prefix)

                    # Verify on receiver that prefix is restored
                    await asyncio.sleep(1.0)
                    is_present = await BGPLabAdapter.is_prefix_present(receiver_id, prefix)
                    if is_present:
                        steps_log.append("Verification: Prefix successfully restored on receiver. Rollback confirmed.")
                        status = "ROLLBACK_SUCCEEDED"
                        break
                    else:
                        steps_log.append(f"Verification: Prefix {prefix} not yet visible on {receiver_id}.")

            except Exception as e:
                steps_log.append(f"Exception during rollback attempt #{retry_count}: {str(e)}")
                logger.error("Rollback attempt #%d failed: %s", retry_count, str(e))

            await asyncio.sleep(1.0)

        if status != "ROLLBACK_SUCCEEDED":
            status = "NEEDS_MANUAL_REVIEW"
            steps_log.append("All rollback retries exhausted without full convergence. Flagged for MANUAL REVIEW.")

        return {
            "status": status,
            "compensating_operation": compensating_op,
            "retries": retry_count,
            "steps": steps_log,
            "original_failure_reason": reason,
        }

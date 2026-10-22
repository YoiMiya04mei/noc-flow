import time
import asyncio
import logging
from typing import Dict, Any, Optional
from app.core.config import settings
from app.schemas.bgp_lab import PostCheckReport
from app.services.bgp_lab_adapter import BGPLabAdapter

logger = logging.getLogger(__name__)


class BGPLabPostCheckEngine:
    """
    Verifies actual routing convergence on receiver speaker after an announce or withdraw.
    """

    @classmethod
    async def verify_announcement_convergence(
        cls,
        receiver_speaker: str,
        prefix: str,
        expected_origin_asn: int,
        expected_nexthop: str,
        timeout_seconds: Optional[int] = None,
    ) -> PostCheckReport:
        timeout = timeout_seconds or settings.BGP_LAB_CONVERGENCE_TIMEOUT_SECONDS
        start_time = time.time()
        poll_interval = 0.5

        logger.info(
            "Verifying announcement convergence for %s on %s (timeout: %ds)",
            prefix, receiver_speaker, timeout
        )

        while time.time() - start_time < timeout:
            rib = await BGPLabAdapter.get_routing_table(receiver_speaker)
            if prefix in rib and len(rib[prefix]) > 0:
                elapsed = round(time.time() - start_time, 2)
                route_data = rib[prefix][0]
                as_path = route_data.get("as_path", "")
                nexthop = route_data.get("next_hop", "")

                # Validate attributes
                has_asn = str(expected_origin_asn) in str(as_path)
                has_nh = (nexthop == expected_nexthop) or (expected_nexthop in str(nexthop))

                details = {
                    "prefix": prefix,
                    "receiver": receiver_speaker,
                    "as_path": as_path,
                    "next_hop": nexthop,
                    "expected_origin_asn": expected_origin_asn,
                    "expected_nexthop": expected_nexthop,
                    "attributes_valid": has_asn,
                    "verified_at_seconds": elapsed,
                }

                if has_asn:
                    return PostCheckReport(
                        overall_status="PASS",
                        convergence_time_seconds=elapsed,
                        details=details,
                    )
                else:
                    return PostCheckReport(
                        overall_status="FAIL",
                        convergence_time_seconds=elapsed,
                        details={
                            **details,
                            "error": f"Route reached receiver but AS_PATH '{as_path}' missing origin {expected_origin_asn}."
                        },
                    )

            await asyncio.sleep(poll_interval)

        elapsed = round(time.time() - start_time, 2)
        return PostCheckReport(
            overall_status="FAIL",
            convergence_time_seconds=elapsed,
            details={
                "prefix": prefix,
                "receiver": receiver_speaker,
                "timeout_seconds": timeout,
                "error": f"Convergence timeout: prefix '{prefix}' was not received by {receiver_speaker} within {timeout}s."
            },
        )

    @classmethod
    async def verify_withdrawal_convergence(
        cls,
        receiver_speaker: str,
        prefix: str,
        timeout_seconds: Optional[int] = None,
    ) -> PostCheckReport:
        timeout = timeout_seconds or settings.BGP_LAB_CONVERGENCE_TIMEOUT_SECONDS
        start_time = time.time()
        poll_interval = 0.5

        logger.info(
            "Verifying withdrawal convergence for %s on %s (timeout: %ds)",
            prefix, receiver_speaker, timeout
        )

        while time.time() - start_time < timeout:
            rib = await BGPLabAdapter.get_routing_table(receiver_speaker)
            if prefix not in rib:
                elapsed = round(time.time() - start_time, 2)
                return PostCheckReport(
                    overall_status="PASS",
                    convergence_time_seconds=elapsed,
                    details={
                        "prefix": prefix,
                        "receiver": receiver_speaker,
                        "verified_absent": True,
                        "verified_at_seconds": elapsed,
                    },
                )

            await asyncio.sleep(poll_interval)

        elapsed = round(time.time() - start_time, 2)
        return PostCheckReport(
            overall_status="FAIL",
            convergence_time_seconds=elapsed,
            details={
                "prefix": prefix,
                "receiver": receiver_speaker,
                "timeout_seconds": timeout,
                "error": f"Withdrawal convergence timeout: prefix '{prefix}' still lingers in {receiver_speaker} routing table after {timeout}s."
            },
        )

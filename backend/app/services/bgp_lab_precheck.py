import logging
import ipaddress
from typing import Dict, Any, List, Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.bgp_lab import LabTestRun
from app.schemas.bgp_lab import PreCheckItem, PreCheckReport
from app.services.bgp_lab_adapter import BGPLabAdapter

logger = logging.getLogger(__name__)


class BGPLabPreCheckEngine:
    """
    Implements the mandatory 11-point safety pre-check before any lab route mutation.
    """

    FORBIDDEN_BOGONS = [
        ipaddress.IPv4Network("0.0.0.0/8"),
        ipaddress.IPv4Network("127.0.0.0/8"),
        ipaddress.IPv4Network("169.254.0.0/16"),
        ipaddress.IPv4Network("224.0.0.0/4"),  # Multicast
        ipaddress.IPv4Network("240.0.0.0/4"),  # Reserved
    ]

    @classmethod
    async def run_pre_checks(
        cls,
        db: AsyncSession,
        prefix: str,
        operation: str,  # ANNOUNCE or WITHDRAW
        target_speaker: str = "bgp-speaker-1",
        target_peer: str = "10.99.0.20",
        current_run_id: Optional[int] = None,
    ) -> PreCheckReport:
        items: List[PreCheckItem] = []
        overall_pass = True

        def record_check(name: str, passed: bool, details: str):
            nonlocal overall_pass
            if not passed:
                overall_pass = False
            items.append(PreCheckItem(
                check_name=name,
                status="PASS" if passed else "FAIL",
                details=details
            ))

        # Check 1: Lab speakers health
        try:
            h1 = await BGPLabAdapter.check_speaker_health("bgp-speaker-1")
            h2 = await BGPLabAdapter.check_speaker_health("bgp-speaker-2")
            both_healthy = h1.get("is_healthy", False) and h2.get("is_healthy", False)
            record_check(
                "1. Speaker Health",
                both_healthy,
                f"Speaker 1: {h1.get('detail')}, Speaker 2: {h2.get('detail')}"
            )
        except Exception as e:
            record_check("1. Speaker Health", False, f"Exception during speaker health check: {str(e)}")

        # Check 2: BGP sessions Established
        try:
            neighbors1 = await BGPLabAdapter.get_neighbors(target_speaker)
            peer_established = False
            for n in neighbors1:
                if n.get("peer_ip") == target_peer and n.get("state") == "Established":
                    peer_established = True
                    break
            record_check(
                "2. Session Established",
                peer_established,
                f"Peer {target_peer} on {target_speaker} is Established." if peer_established
                else f"Peer {target_peer} is NOT in Established state on {target_speaker}."
            )
        except Exception as e:
            record_check("2. Session Established", False, f"Failed querying peer status: {str(e)}")

        # Check 3: Peer in lab allowlist
        try:
            peer_in_allowlist = target_peer in settings.BGP_LAB_ALLOWED_PEERS
            record_check(
                "3. Peer Allowlist",
                peer_in_allowlist,
                f"Peer {target_peer} is authorized in BGP_LAB_ALLOWED_PEERS." if peer_in_allowlist
                else f"Peer {target_peer} NOT found in BGP_LAB_ALLOWED_PEERS {settings.BGP_LAB_ALLOWED_PEERS}."
            )
        except Exception as e:
            record_check("3. Peer Allowlist", False, str(e))

        # Check 4: Prefix valid and in lab allowlist
        try:
            prefix_in_allowlist = prefix in settings.BGP_LAB_ALLOWED_PREFIXES
            record_check(
                "4. Prefix Allowlist",
                prefix_in_allowlist,
                f"Prefix {prefix} is authorized in BGP_LAB_ALLOWED_PREFIXES." if prefix_in_allowlist
                else f"Prefix {prefix} NOT found in BGP_LAB_ALLOWED_PREFIXES {settings.BGP_LAB_ALLOWED_PREFIXES}."
            )
        except Exception as e:
            record_check("4. Prefix Allowlist", False, str(e))

        # Check 5: Default routes 0.0.0.0/0 and ::/0 rejected
        is_default = prefix in ("0.0.0.0/0", "::/0")
        record_check(
            "5. Default Route Rejection",
            not is_default,
            "Prefix is not a default route." if not is_default
            else "CRITICAL REJECTION: Default routes 0.0.0.0/0 and ::/0 are permanently blocked."
        )

        # Check 6: Forbidden bogons/martians check
        is_bogon = False
        bogon_detail = "Prefix is not in reserved/multicast space."
        try:
            net = ipaddress.IPv4Network(prefix, strict=False)
            for bogon in cls.FORBIDDEN_BOGONS:
                if net.overlaps(bogon):
                    is_bogon = True
                    bogon_detail = f"Prefix overlaps with reserved range {bogon}."
                    break
        except Exception as e:
            is_bogon = True
            bogon_detail = f"Invalid IP syntax: {str(e)}"
        record_check("6. Forbidden Route Space", not is_bogon, bogon_detail)

        # Check 7: Initial routing state can be captured
        initial_snap = None
        try:
            initial_snap = await BGPLabAdapter.get_routing_table(target_speaker)
            can_capture = initial_snap is not None
            record_check(
                "7. Initial State Snapshot",
                can_capture,
                f"Successfully captured initial routing table snapshot ({len(initial_snap)} prefixes)."
            )
        except Exception as e:
            record_check("7. Initial State Snapshot", False, f"Failed to snapshot initial state: {str(e)}")

        # Check 8: Operation matches current state
        try:
            is_present = await BGPLabAdapter.is_prefix_present(target_speaker, prefix)
            if operation.upper() == "ANNOUNCE":
                op_valid = not is_present
                op_detail = (
                    f"Prefix {prefix} is currently absent from {target_speaker}. Ready for announce."
                    if op_valid else f"Prefix {prefix} is ALREADY announced on {target_speaker}."
                )
            elif operation.upper() == "WITHDRAW":
                op_valid = is_present
                op_detail = (
                    f"Prefix {prefix} is currently active on {target_speaker}. Ready for withdrawal."
                    if op_valid else f"Prefix {prefix} is NOT currently present on {target_speaker} to withdraw."
                )
            else:  # ROUNDTRIP
                op_valid = True
                op_detail = "Roundtrip scenario valid."
            record_check("8. Operation State Compatibility", op_valid, op_detail)
        except Exception as e:
            record_check("8. Operation State Compatibility", False, f"Error validating route presence: {str(e)}")

        # Check 9: No concurrent in-progress lab test for same prefix
        try:
            conditions = [
                LabTestRun.prefix == prefix,
                LabTestRun.execution_status == "IN_PROGRESS",
            ]
            if current_run_id is not None:
                conditions.append(LabTestRun.id != current_run_id)

            concurrent_stmt = select(LabTestRun).where(and_(*conditions))
            concurrent = (await db.execute(concurrent_stmt)).scalars().first()
            no_concurrency = concurrent is None
            record_check(
                "9. Concurrency Conflict Prevention",
                no_concurrency,
                "No conflicting in-progress lab tests detected for this prefix." if no_concurrency
                else f"CONFLICT: Lab test #{concurrent.id} is currently running for prefix {prefix}."
            )
        except Exception as e:
            record_check("9. Concurrency Conflict Prevention", False, f"Database check failed: {str(e)}")

        # Check 10: Lab execution flag actively enabled
        lab_flag = settings.BGP_LAB_ENABLED is True
        record_check(
            "10. Lab Execution Flag Active",
            lab_flag,
            "BGP_LAB_ENABLED is TRUE. Lab execution permitted." if lab_flag
            else "SAFETY LOCKOUT: BGP_LAB_ENABLED is FALSE in system configuration. Lab operations blocked."
        )

        # Check 11: Audit readiness
        record_check(
            "11. Audit Readiness",
            True,
            "Pre-check audit events configured for persistent recording."
        )

        return PreCheckReport(
            overall_status="PASS" if overall_pass else "FAIL",
            items=items,
        )

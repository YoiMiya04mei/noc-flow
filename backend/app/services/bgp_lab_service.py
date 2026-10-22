import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.bgp_lab import LabTestRun
from app.models.recommendation import ChangeRequest
from app.models.user import User
from app.schemas.bgp_lab import (
    LabStatusResponse,
    LabSpeakerStatus,
    LabPeerStatus,
    PreCheckReport,
    PostCheckReport,
)
from app.services.bgp_lab_adapter import BGPLabAdapter
from app.services.bgp_lab_precheck import BGPLabPreCheckEngine
from app.services.bgp_lab_postcheck import BGPLabPostCheckEngine
from app.services.bgp_lab_rollback import AutomatedRollbackCoordinator
from app.api.deps import record_audit_event

logger = logging.getLogger(__name__)


class BGPLabService:
    """
    Orchestration service for Isolated BGP Lab tests, convergence verification,
    Change Request linking, and automated rollbacks.
    """

    @classmethod
    async def get_lab_status(cls, db: AsyncSession) -> LabStatusResponse:
        speakers = []
        for s_id in ["bgp-speaker-1", "bgp-speaker-2"]:
            cfg = BGPLabAdapter.get_speaker_config(s_id)
            health = await BGPLabAdapter.check_speaker_health(s_id)
            raw_peers = await BGPLabAdapter.get_neighbors(s_id)
            routing_table = await BGPLabAdapter.get_routing_table(s_id)

            peers_list = [
                LabPeerStatus(
                    peer_ip=p["peer_ip"],
                    peer_as=p["peer_as"],
                    local_as=p["local_as"],
                    state=p["state"],
                    uptime_seconds=p["uptime_seconds"],
                    prefixes_received=len(routing_table) if p["peer_ip"] == cfg["peer_ip"] else 0,
                    prefixes_advertised=len(routing_table) if s_id == "bgp-speaker-1" else 0,
                    router_id=p.get("router_id"),
                )
                for p in raw_peers
            ]

            speakers.append(
                LabSpeakerStatus(
                    speaker_id=s_id,
                    name=f"Isolated BGP Lab - {s_id.upper()}",
                    asn=cfg["asn"],
                    ip_address=cfg["ip"],
                    is_healthy=health.get("is_healthy", False),
                    status_detail=health.get("detail", "Unknown"),
                    peers=peers_list,
                    active_routes_count=len(routing_table),
                )
            )

        active_tests_stmt = select(LabTestRun).where(LabTestRun.execution_status == "IN_PROGRESS")
        active_tests = (await db.execute(active_tests_stmt)).scalars().all()

        return LabStatusResponse(
            lab_enabled=settings.BGP_LAB_ENABLED,
            lab_mode=settings.BGP_LAB_MODE,
            speakers=speakers,
            allowed_prefixes=settings.BGP_LAB_ALLOWED_PREFIXES,
            allowed_peers=settings.BGP_LAB_ALLOWED_PEERS,
            active_tests_count=len(active_tests),
        )

    @classmethod
    async def run_announce_test(
        cls,
        db: AsyncSession,
        prefix: str,
        target_speaker: str = "bgp-speaker-1",
        change_request_id: Optional[int] = None,
        operator: Optional[User] = None,
        request: Optional[Any] = None,
    ) -> LabTestRun:
        speaker_cfg = BGPLabAdapter.get_speaker_config(target_speaker)
        receiver_id = "bgp-speaker-2" if target_speaker == "bgp-speaker-1" else "bgp-speaker-1"
        receiver_cfg = BGPLabAdapter.get_speaker_config(receiver_id)

        # 1. Capture Initial Snapshots
        init_sender_rib = await BGPLabAdapter.get_routing_table(target_speaker)
        init_receiver_rib = await BGPLabAdapter.get_routing_table(receiver_id)
        initial_snapshot = {
            "sender_rib": init_sender_rib,
            "receiver_rib": init_receiver_rib,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 2. Record LabTestRun record in PENDING state
        test_run = LabTestRun(
            change_request_id=change_request_id,
            test_type="ANNOUNCE",
            target_speaker=target_speaker,
            target_peer=speaker_cfg["peer_ip"],
            prefix=prefix,
            pre_check_status="PENDING",
            post_check_status="PENDING",
            execution_status="IN_PROGRESS",
            rollback_status="NONE",
            initial_snapshot=json.dumps(initial_snapshot),
            operator_id=operator.id if operator else None,
        )
        db.add(test_run)
        await db.commit()
        await db.refresh(test_run)

        # 3. Run Pre-Check (11 mandatory points)
        precheck_report: PreCheckReport = await BGPLabPreCheckEngine.run_pre_checks(
            db=db,
            prefix=prefix,
            operation="ANNOUNCE",
            target_speaker=target_speaker,
            target_peer=speaker_cfg["peer_ip"],
            current_run_id=test_run.id,
        )
        test_run.pre_check_status = precheck_report.overall_status
        test_run.pre_check_details = json.dumps([item.model_dump() for item in precheck_report.items])

        if precheck_report.overall_status != "PASS":
            test_run.execution_status = "FAILED"
            test_run.completed_at = datetime.now(timezone.utc)
            test_run.error_message = "PRE-CHECK FAILED: One or more safety criteria not met."
            await db.commit()
            await db.refresh(test_run)

            await record_audit_event(
                db=db,
                user=operator,
                action="BGP_LAB_ANNOUNCE_PRECHECK_FAILED",
                resource_type="lab_test_run",
                resource_id=str(test_run.id),
                details=f"Pre-check failed for prefix {prefix} on {target_speaker}.",
                request=request,
            )
            return test_run

        # 4. Execute Route Announcement on Sender
        try:
            await BGPLabAdapter.announce_prefix(
                speaker_id=target_speaker,
                prefix=prefix,
                next_hop=speaker_cfg["ip"],
            )
        except Exception as e:
            test_run.execution_status = "FAILED"
            test_run.error_message = f"Announcement command failed: {str(e)}"
            test_run.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return test_run

        # 5. Run Post-Check Convergence Verification on Receiver
        postcheck_report: PostCheckReport = await BGPLabPostCheckEngine.verify_announcement_convergence(
            receiver_speaker=receiver_id,
            prefix=prefix,
            expected_origin_asn=speaker_cfg["asn"],
            expected_nexthop=speaker_cfg["ip"],
        )
        test_run.post_check_status = postcheck_report.overall_status
        test_run.post_check_details = json.dumps(postcheck_report.model_dump())

        # 6. Handle Success or Automated Rollback
        if postcheck_report.overall_status == "PASS":
            test_run.execution_status = "SUCCESS"
            test_run.rollback_status = "NONE"

            # If linked to a Change Request, mark lab_tested = True
            if change_request_id:
                cr_stmt = select(ChangeRequest).where(ChangeRequest.id == change_request_id)
                cr = (await db.execute(cr_stmt)).scalars().first()
                if cr:
                    cr.lab_tested = True
                    cr.lab_test_run_id = test_run.id

            await record_audit_event(
                db=db,
                user=operator,
                action="BGP_LAB_ANNOUNCE_SUCCESS",
                resource_type="lab_test_run",
                resource_id=str(test_run.id),
                details=f"Prefix {prefix} successfully announced and verified on {receiver_id} in {postcheck_report.convergence_time_seconds}s.",
                request=request,
            )
        else:
            # Post-check failed! Trigger automated rollback!
            logger.warning("Post-check failed for prefix %s. Initiating automated rollback.", prefix)
            rollback_res = await AutomatedRollbackCoordinator.execute_rollback(
                operation="ANNOUNCE",
                speaker_id=target_speaker,
                receiver_id=receiver_id,
                prefix=prefix,
                initial_snapshot=initial_snapshot,
                reason=postcheck_report.details.get("error", "Post-check convergence failed"),
            )
            test_run.execution_status = "ROLLED_BACK"
            test_run.rollback_status = rollback_res["status"]
            test_run.rollback_details = json.dumps(rollback_res)
            test_run.error_message = postcheck_report.details.get("error", "Convergence failed; rolled back.")

            await record_audit_event(
                db=db,
                user=operator,
                action="BGP_LAB_ANNOUNCE_ROLLED_BACK",
                resource_type="lab_test_run",
                resource_id=str(test_run.id),
                details=f"Prefix {prefix} announcement failed post-check. Rollback result: {rollback_res['status']}.",
                request=request,
            )

        # 7. Final Snapshot & Completion
        final_sender_rib = await BGPLabAdapter.get_routing_table(target_speaker)
        final_receiver_rib = await BGPLabAdapter.get_routing_table(receiver_id)
        test_run.final_snapshot = json.dumps({
            "sender_rib": final_sender_rib,
            "receiver_rib": final_receiver_rib,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        test_run.completed_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(test_run)
        return test_run

    @classmethod
    async def run_withdraw_test(
        cls,
        db: AsyncSession,
        prefix: str,
        target_speaker: str = "bgp-speaker-1",
        change_request_id: Optional[int] = None,
        operator: Optional[User] = None,
        request: Optional[Any] = None,
    ) -> LabTestRun:
        speaker_cfg = BGPLabAdapter.get_speaker_config(target_speaker)
        receiver_id = "bgp-speaker-2" if target_speaker == "bgp-speaker-1" else "bgp-speaker-1"

        # 1. Capture Initial Snapshots
        init_sender_rib = await BGPLabAdapter.get_routing_table(target_speaker)
        init_receiver_rib = await BGPLabAdapter.get_routing_table(receiver_id)
        initial_snapshot = {
            "sender_rib": init_sender_rib,
            "receiver_rib": init_receiver_rib,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 2. Record LabTestRun
        test_run = LabTestRun(
            change_request_id=change_request_id,
            test_type="WITHDRAW",
            target_speaker=target_speaker,
            target_peer=speaker_cfg["peer_ip"],
            prefix=prefix,
            pre_check_status="PENDING",
            post_check_status="PENDING",
            execution_status="IN_PROGRESS",
            rollback_status="NONE",
            initial_snapshot=json.dumps(initial_snapshot),
            operator_id=operator.id if operator else None,
        )
        db.add(test_run)
        await db.commit()
        await db.refresh(test_run)

        # 3. Pre-Check
        precheck_report = await BGPLabPreCheckEngine.run_pre_checks(
            db=db,
            prefix=prefix,
            operation="WITHDRAW",
            target_speaker=target_speaker,
            target_peer=speaker_cfg["peer_ip"],
            current_run_id=test_run.id,
        )
        test_run.pre_check_status = precheck_report.overall_status
        test_run.pre_check_details = json.dumps([item.model_dump() for item in precheck_report.items])

        if precheck_report.overall_status != "PASS":
            test_run.execution_status = "FAILED"
            test_run.completed_at = datetime.now(timezone.utc)
            test_run.error_message = "PRE-CHECK FAILED: One or more safety criteria not met."
            await db.commit()
            return test_run

        # 4. Execute Route Withdrawal
        try:
            await BGPLabAdapter.withdraw_prefix(speaker_id=target_speaker, prefix=prefix)
        except Exception as e:
            test_run.execution_status = "FAILED"
            test_run.error_message = f"Withdrawal command failed: {str(e)}"
            test_run.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return test_run

        # 5. Run Post-Check
        postcheck_report = await BGPLabPostCheckEngine.verify_withdrawal_convergence(
            receiver_speaker=receiver_id,
            prefix=prefix,
        )
        test_run.post_check_status = postcheck_report.overall_status
        test_run.post_check_details = json.dumps(postcheck_report.model_dump())

        # 6. Handle Success or Rollback
        if postcheck_report.overall_status == "PASS":
            test_run.execution_status = "SUCCESS"
            test_run.rollback_status = "NONE"

            if change_request_id:
                cr_stmt = select(ChangeRequest).where(ChangeRequest.id == change_request_id)
                cr = (await db.execute(cr_stmt)).scalars().first()
                if cr:
                    cr.lab_tested = True
                    cr.lab_test_run_id = test_run.id

            await record_audit_event(
                db=db,
                user=operator,
                action="BGP_LAB_WITHDRAW_SUCCESS",
                resource_type="lab_test_run",
                resource_id=str(test_run.id),
                details=f"Prefix {prefix} withdrawn and verified absent on {receiver_id} in {postcheck_report.convergence_time_seconds}s.",
                request=request,
            )
        else:
            # Post-check failed!
            rollback_res = await AutomatedRollbackCoordinator.execute_rollback(
                operation="WITHDRAW",
                speaker_id=target_speaker,
                receiver_id=receiver_id,
                prefix=prefix,
                initial_snapshot=initial_snapshot,
                reason=postcheck_report.details.get("error", "Withdrawal convergence failed"),
            )
            test_run.execution_status = "ROLLED_BACK"
            test_run.rollback_status = rollback_res["status"]
            test_run.rollback_details = json.dumps(rollback_res)
            test_run.error_message = postcheck_report.details.get("error", "Withdrawal failed to converge.")

            await record_audit_event(
                db=db,
                user=operator,
                action="BGP_LAB_WITHDRAW_ROLLED_BACK",
                resource_type="lab_test_run",
                resource_id=str(test_run.id),
                details=f"Prefix {prefix} withdrawal failed post-check. Rollback result: {rollback_res['status']}.",
                request=request,
            )

        # 7. Final Snapshot
        final_sender_rib = await BGPLabAdapter.get_routing_table(target_speaker)
        final_receiver_rib = await BGPLabAdapter.get_routing_table(receiver_id)
        test_run.final_snapshot = json.dumps({
            "sender_rib": final_sender_rib,
            "receiver_rib": final_receiver_rib,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        test_run.completed_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(test_run)
        return test_run

    @classmethod
    async def run_roundtrip_test(
        cls,
        db: AsyncSession,
        prefix: str,
        target_speaker: str = "bgp-speaker-1",
        change_request_id: Optional[int] = None,
        operator: Optional[User] = None,
        request: Optional[Any] = None,
    ) -> LabTestRun:
        """
        Executes full roundtrip integration test:
        1. Announce prefix -> Verify on receiver
        2. Withdraw prefix -> Verify purged from receiver
        """
        # Part 1: Announce
        announce_run = await cls.run_announce_test(
            db=db,
            prefix=prefix,
            target_speaker=target_speaker,
            change_request_id=change_request_id,
            operator=operator,
            request=request,
        )
        if announce_run.execution_status != "SUCCESS":
            announce_run.test_type = "ROUNDTRIP"
            await db.commit()
            return announce_run

        # Part 2: Withdraw
        withdraw_run = await cls.run_withdraw_test(
            db=db,
            prefix=prefix,
            target_speaker=target_speaker,
            change_request_id=change_request_id,
            operator=operator,
            request=request,
        )
        withdraw_run.test_type = "ROUNDTRIP"
        await db.commit()
        await db.refresh(withdraw_run)
        return withdraw_run

    @classmethod
    async def complete_manual_review(
        cls,
        db: AsyncSession,
        test_run_id: int,
        operator: User,
        notes: str,
        request: Optional[Any] = None,
    ) -> LabTestRun:
        test_run = await db.get(LabTestRun, test_run_id)
        if not test_run:
            raise ValueError(f"LabTestRun {test_run_id} not found.")

        if test_run.rollback_status != "NEEDS_MANUAL_REVIEW":
            raise ValueError(f"Test run {test_run_id} does not require manual review (status: {test_run.rollback_status}).")

        test_run.rollback_status = "MANUAL_REVIEW_RESOLVED"
        test_run.error_message = f"{test_run.error_message or ''} | Manual review resolved by {operator.username}: {notes}"

        await db.commit()
        await db.refresh(test_run)

        await record_audit_event(
            db=db,
            user=operator,
            action="BGP_LAB_MANUAL_REVIEW_COMPLETED",
            resource_type="lab_test_run",
            resource_id=str(test_run.id),
            details=f"Manual review completed for test #{test_run.id} by {operator.username}. Notes: {notes}",
            request=request,
        )
        return test_run

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal, engine
from app.core.security import get_password_hash
from app.models.base import Base
from app.models.user import User, UserRole, UserStatus
from app.models.inventory import Site, Provider, Device, Interface, Collector
from app.models.policy import PrefixAllowlist, PeerAllowlist, ScoringPolicy
from app.models.bgp import BGPPeer, RouteEvent, BGPRoute
from app.models.probe import ProbeTarget, ProbeResult
from app.models.recommendation import Recommendation, ChangeRequest
from app.models.alert import AlertRule, AlertIncident
from app.models.audit import AuditEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed")


async def seed_database():
    logger.info("Initializing schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # 1. Seed Users (All 5 Roles for RBAC validation)
        existing_admin = await session.execute(select(User).where(User.username == "admin"))
        if not existing_admin.scalars().first():
            logger.info("Seeding system users across RBAC roles...")
            users = [
                User(
                    username="admin",
                    email="admin@jdp-noc.net",
                    full_name="Super Administrator",
                    password_hash=get_password_hash("Admin@JDP2026!noc"),
                    role=UserRole.SUPER_ADMIN.value,
                    status=UserStatus.ACTIVE.value,
                ),
                User(
                    username="engineer1",
                    email="engineer@jdp-noc.net",
                    full_name="Senior Network Engineer",
                    password_hash=get_password_hash("Engineer@JDP2026!"),
                    role=UserRole.NETWORK_ENGINEER.value,
                    status=UserStatus.ACTIVE.value,
                ),
                User(
                    username="lead_approver",
                    email="approver@jdp-noc.net",
                    full_name="NOC Lead Approver",
                    password_hash=get_password_hash("Approver@JDP2026!"),
                    role=UserRole.APPROVER.value,
                    status=UserStatus.ACTIVE.value,
                ),
                User(
                    username="operator1",
                    email="operator@jdp-noc.net",
                    full_name="NOC Shift Operator",
                    password_hash=get_password_hash("Operator@JDP2026!"),
                    role=UserRole.NOC_OPERATOR.value,
                    status=UserStatus.ACTIVE.value,
                ),
                User(
                    username="auditor1",
                    email="auditor@jdp-noc.net",
                    full_name="Compliance Auditor",
                    password_hash=get_password_hash("Auditor@JDP2026!"),
                    role=UserRole.AUDITOR.value,
                    status=UserStatus.ACTIVE.value,
                ),
            ]
            session.add_all(users)
            await session.commit()

        # 2. Seed Sites & Providers
        site1 = (await session.execute(select(Site).where(Site.code == "POP-CGK-1"))).scalars().first()
        site2 = (await session.execute(select(Site).where(Site.code == "POP-SUB-1"))).scalars().first()
        if not site1:
            logger.info("Seeding Sites, Providers, and Device Inventory...")
            site1 = Site(name="Jakarta Datacenter IDC 3D", code="POP-CGK-1", location="Jakarta, Indonesia")
            site2 = Site(name="Surabaya POP Intiland", code="POP-SUB-1", location="Surabaya, Indonesia")
            session.add_all([site1, site2])
            await session.commit()
            await session.refresh(site1)
            await session.refresh(site2)

        prov1 = (await session.execute(select(Provider).where(Provider.provider_asn == 7713))).scalars().first()
        prov2 = (await session.execute(select(Provider).where(Provider.provider_asn == 4761))).scalars().first()
        prov3 = (await session.execute(select(Provider).where(Provider.provider_asn == 3356))).scalars().first()
        if not prov1:
            prov1 = Provider(name="Telkom DWS (AS7713)", provider_asn=7713, cost_weight=1.0, capacity_bps=40_000_000_000)
            prov2 = Provider(name="Indosat Ooredoo (AS4761)", provider_asn=4761, cost_weight=1.2, capacity_bps=20_000_000_000)
            prov3 = Provider(name="Lumen / Level3 (AS3356)", provider_asn=3356, cost_weight=2.0, capacity_bps=10_000_000_000)
            session.add_all([prov1, prov2, prov3])
            await session.commit()
            await session.refresh(prov1)
            await session.refresh(prov2)

        dev1 = (await session.execute(select(Device).where(Device.hostname == "cr01.cgk.jdp.net"))).scalars().first()
        dev2 = (await session.execute(select(Device).where(Device.hostname == "cr02.cgk.jdp.net"))).scalars().first()
        dev3 = (await session.execute(select(Device).where(Device.hostname == "er01.sub.jdp.net"))).scalars().first()
        if not dev1:
            dev1 = Device(hostname="cr01.cgk.jdp.net", mgmt_ip="10.250.0.1", vendor="Juniper", model="MX480", site_id=site1.id)
            dev2 = Device(hostname="cr02.cgk.jdp.net", mgmt_ip="10.250.0.2", vendor="Cisco", model="ASR9006", site_id=site1.id)
            dev3 = Device(hostname="er01.sub.jdp.net", mgmt_ip="10.250.1.1", vendor="Huawei", model="NetEngine 40E", site_id=site2.id)
            session.add_all([dev1, dev2, dev3])
            await session.commit()
            await session.refresh(dev1)

        # 3. Interfaces & Dependent Telemetry
        existing_if = (await session.execute(select(Interface).where(Interface.device_id == dev1.id))).scalars().first()
        if not existing_if:
            logger.info("Seeding Interfaces, Collectors, Peers, and Routes...")
            # Interfaces
            if1 = Interface(device_id=dev1.id, if_index=1, if_name="xe-0/0/0", alias="Transit Telkom DWS 40G", speed_bps=40_000_000_000, in_bps=22_400_000_000, out_bps=8_100_000_000, utilization_pct=56.0)
            if2 = Interface(device_id=dev1.id, if_index=2, if_name="xe-0/0/1", alias="Transit Indosat 20G", speed_bps=20_000_000_000, in_bps=14_800_000_000, out_bps=5_200_000_000, utilization_pct=74.0)
            if3 = Interface(device_id=dev1.id, if_index=3, if_name="xe-0/0/2", alias="Inter-POP Ring Sub", speed_bps=100_000_000_000, in_bps=38_000_000_000, out_bps=31_000_000_000, utilization_pct=38.0)
            session.add_all([if1, if2, if3])

            # Collectors
            col1 = Collector(name="Collector-CGK-Primary", host="10.250.0.50", port=2055, collector_type="netflow", site_id=site1.id, packets_received=142_500_000, flows_parsed=980_000_000, parse_errors=12)
            col2 = Collector(name="Collector-SUB-Secondary", host="10.250.1.50", port=6343, collector_type="sflow", site_id=site2.id, packets_received=45_000_000, flows_parsed=310_000_000, parse_errors=4)
            session.add_all([col1, col2])

            # BGP Peers
            peer1 = BGPPeer(device_id=dev1.id, peer_ip="198.51.100.1", local_as=136052, remote_as=7713, peer_name="Telkom DWS Transit", state="Established", uptime_seconds=2540000, prefixes_received=945200, prefixes_advertised=12, data_source="simulated")
            peer2 = BGPPeer(device_id=dev1.id, peer_ip="198.51.100.5", local_as=136052, remote_as=4761, peer_name="Indosat Ooredoo Transit", state="Established", uptime_seconds=1840000, prefixes_received=942100, prefixes_advertised=12, data_source="simulated")
            session.add_all([peer1, peer2])

            # Initial BGP Routes
            route1 = BGPRoute(prefix="1.1.1.0/24", peer_ip="198.51.100.1", peer_asn=7713, best_path="AS13335 (Cloudflare)", next_hop="198.51.100.1", as_path="7713 13335", origin="IGP", communities="7713:100", data_source="simulated", is_active=True)
            route2 = BGPRoute(prefix="8.8.8.0/24", peer_ip="198.51.100.5", peer_asn=4761, best_path="AS15169 (Google)", next_hop="198.51.100.5", as_path="4761 15169", origin="IGP", communities="4761:300", data_source="simulated", is_active=True)
            route3 = BGPRoute(prefix="208.67.222.0/24", peer_ip="198.51.100.1", peer_asn=7713, best_path="AS36692 (OpenDNS)", next_hop="198.51.100.1", as_path="7713 36692", origin="IGP", communities="7713:100", data_source="simulated", is_active=True)
            session.add_all([route1, route2, route3])

            # Prefix Allowlists (Deny-by-default guardrail baseline)
            allowlist1 = PrefixAllowlist(prefix="103.145.2.0/24", description="Customer Core Block A - Subnet JDP", is_active=True)
            allowlist2 = PrefixAllowlist(prefix="103.145.3.0/24", description="Customer Core Block B - Subnet JDP", is_active=True)
            session.add_all([allowlist1, allowlist2])

            # Scoring Policy
            policy1 = ScoringPolicy(name="Balanced Latency and Cost ISP Policy", latency_weight=0.40, loss_weight=0.30, jitter_weight=0.15, cost_weight=0.15, hold_down_minutes=15, hysteresis_threshold_pct=15.0)
            session.add(policy1)

            # Recommendations & Change Requests
            rec1 = Recommendation(
                prefix="103.145.2.0/24",
                current_path="AS7713 (Telkom DWS)",
                candidate_path="AS4761 (Indosat Ooredoo)",
                score_current=64.2,
                score_candidate=88.7,
                confidence_pct=92.0,
                reason="Observed 28ms lower RTT and 0.0% loss via AS4761 to Singapore Cloudflare / AWS edges over 6 hours baseline.",
                risk_level="low",
                status="generated",
                policy_id=policy1.id,
                score_breakdown=json.dumps({
                    "composite_score": 88.7,
                    "convention": "HIGHER_IS_BETTER (0.0 to 100.0)",
                    "policy_name": "Balanced Latency and Cost ISP Policy",
                    "metrics": [
                        {"metric_name": "latency", "raw_value": 24.8, "unit": "ms", "normalized_score": 90.1, "weight": 0.40, "weighted_contribution": 36.04, "status": "valid"},
                        {"metric_name": "packet_loss", "raw_value": 0.0, "unit": "%", "normalized_score": 100.0, "weight": 0.30, "weighted_contribution": 30.0, "status": "valid"},
                        {"metric_name": "jitter", "raw_value": 1.6, "unit": "ms", "normalized_score": 94.7, "weight": 0.15, "weighted_contribution": 14.21, "status": "valid"},
                        {"metric_name": "utilization", "raw_value": 45.0, "unit": "%", "normalized_score": 55.0, "weight": 0.10, "weighted_contribution": 5.5, "status": "valid"},
                        {"metric_name": "cost", "raw_value": 4.2, "unit": "USD/Mbps", "normalized_score": 79.0, "weight": 0.05, "weighted_contribution": 3.95, "status": "valid"}
                    ]
                }),
                current_metrics=json.dumps({"latency_ms": 52.8, "loss_percent": 1.2, "jitter_ms": 5.4, "utilization_pct": 65.0, "cost_per_mbps": 5.5}),
                candidate_metrics=json.dumps({"latency_ms": 24.8, "loss_percent": 0.0, "jitter_ms": 1.6, "utilization_pct": 45.0, "cost_per_mbps": 4.2}),
                data_quality=json.dumps({
                    "confidence_pct": 92.0,
                    "freshness_seconds": 25,
                    "sources_available": ["BGP", "ACTIVE_PROBE", "SNMP", "CLICKHOUSE_FLOW"],
                    "missing_sources": [],
                    "is_stale": False,
                    "is_insufficient_data": False,
                    "explanation": "High-confidence telemetry from all primary sources with active probe data fresh within 25 seconds."
                }),
                rejection_reasons=json.dumps([]),
                input_snapshot_hash="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            )
            session.add(rec1)
            await session.commit()
            await session.refresh(rec1)

            # Change Request (Linked to rec1)
            eng_user = await session.execute(select(User).where(User.username == "engineer1"))
            engineer = eng_user.scalars().first()
            if engineer:
                cr1 = ChangeRequest(
                    recommendation_id=rec1.id,
                    requester_id=engineer.id,
                    target_peer="198.51.100.5 (Indosat Ooredoo)",
                    prefix="103.145.2.0/24",
                    diff_payload="router bgp 136052\n neighbor 198.51.100.5 route-map RM-ALLOW-IN permit 10\n set local-preference 200",
                    justification="Shift traffic to Indosat AS4761 for 28ms lower RTT to Singapore Cloudflare / AWS edge.",
                    validation_status="valid",
                    execution_status="pending_approval",
                    requires_dual_approval=True,
                    rollback_instructions="router bgp 136052\n no neighbor 198.51.100.5 route-map RM-ALLOW-IN permit 10\n set local-preference 100",
                )
                session.add(cr1)
                await session.commit()

            # Probe Targets
            now_dt = datetime.now(timezone.utc)
            tgt1 = ProbeTarget(target_ip="1.1.1.1", target_name="Cloudflare Anycast SG", probe_type="icmp", provider_id=prov1.id, interval_seconds=15, last_latency_ms=14.2, last_loss_percent=0.0, last_status="ok", last_probed_at=now_dt)
            tgt2 = ProbeTarget(target_ip="8.8.8.8", target_name="Google DNS Egress", probe_type="icmp", provider_id=prov2.id, interval_seconds=15, last_latency_ms=18.6, last_loss_percent=0.0, last_status="ok", last_probed_at=now_dt)
            tgt3 = ProbeTarget(target_ip="1.0.0.1", target_name="Cloudflare DoH TCP", probe_type="tcp", port=443, provider_id=prov1.id, interval_seconds=15, last_latency_ms=15.1, last_loss_percent=0.0, last_status="ok", last_probed_at=now_dt)
            session.add_all([tgt1, tgt2, tgt3])
            await session.commit()
            await session.refresh(tgt1)
            await session.refresh(tgt2)
            await session.refresh(tgt3)

            # Initial Probe Results
            res1 = ProbeResult(target_id=tgt1.id, provider_id=prov1.id, latency_ms=14.2, min_latency_ms=13.8, max_latency_ms=14.6, loss_percent=0.0, jitter_ms=0.4, status="ok", egress_mode="source_ip_bind", data_source="simulated", timestamp=now_dt)
            res2 = ProbeResult(target_id=tgt2.id, provider_id=prov2.id, latency_ms=18.6, min_latency_ms=18.0, max_latency_ms=19.2, loss_percent=0.0, jitter_ms=0.6, status="ok", egress_mode="source_ip_bind", data_source="simulated", timestamp=now_dt)
            res3 = ProbeResult(target_id=tgt3.id, provider_id=prov1.id, latency_ms=15.1, min_latency_ms=14.7, max_latency_ms=15.8, loss_percent=0.0, jitter_ms=0.5, status="ok", egress_mode="source_ip_bind", data_source="simulated", timestamp=now_dt)
            session.add_all([res1, res2, res3])

            # Alert Rules & Incidents
            rule1 = AlertRule(name="Interface Utilization > 70%", rule_type="interface_utilization", severity="warning", threshold_value=70.0)
            rule2 = AlertRule(name="BGP Peer Session Down", rule_type="bgp_peer_down", severity="critical", threshold_value=1.0)
            session.add_all([rule1, rule2])
            await session.commit()
            await session.refresh(rule1)

            incident1 = AlertIncident(
                rule_id=rule1.id,
                severity="warning",
                title="High Bandwidth Utilization on Uplink Indosat 20G",
                description="Interface xe-0/0/1 on cr01.cgk.jdp.net exceeded 70% utilization threshold (currently 74%).",
                target_entity="cr01.cgk.jdp.net:xe-0/0/1",
                status="active",
            )
            session.add(incident1)

            # Initial Audit event
            audit1 = AuditEvent(
                actor_username="system",
                actor_role="system",
                action="SYSTEM_INIT",
                resource_type="system",
                resource_id="1",
                details="Initial platform seeding completed successfully. ROUTING_EXECUTION_ENABLED is locked to false.",
                ip_address="127.0.0.1",
            )
            session.add(audit1)
            await session.commit()

            logger.info("Database seeding completed successfully.")


if __name__ == "__main__":
    asyncio.run(seed_database())

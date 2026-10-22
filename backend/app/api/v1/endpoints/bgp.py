from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, status, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.bgp import BGPPeer, RouteEvent, BGPRoute
from app.schemas.bgp import (
    BGPPeerResponse,
    RouteEventResponse,
    BGPRouteResponse,
    BMPStatusResponse,
    BMPSimulateRequest,
)
from app.api.deps import get_current_user, require_roles, record_audit_event
from app.services.bmp_service import bmp_adapter_service
from app.services.bmp_simulator import (
    build_bmp_initiation,
    build_bmp_peer_up,
    build_bmp_route_monitoring,
    build_bmp_peer_down,
)

router = APIRouter()


@router.get("/peers", response_model=List[BGPPeerResponse])
async def list_bgp_peers(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns all monitored BGP peering sessions with state and telemetry origin."""
    stmt = select(BGPPeer).order_by(BGPPeer.id.asc())
    peers = (await db.execute(stmt)).scalars().all()
    return peers


@router.get("/peers/{peer_id}", response_model=BGPPeerResponse)
async def get_bgp_peer(
    peer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns specific BGP peer details."""
    peer = await db.get(BGPPeer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"BGP peer with id={peer_id} not found")
    return peer


@router.get("/events", response_model=List[RouteEventResponse])
async def list_route_events(
    prefix: Optional[str] = Query(None),
    peer_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns historical route events (ANNOUNCE, WITHDRAW, STATE_CHANGE)."""
    stmt = select(RouteEvent)
    if prefix:
        stmt = stmt.where(RouteEvent.prefix == prefix)
    if peer_ip:
        stmt = stmt.where(RouteEvent.peer_ip == peer_ip)
    if event_type:
        stmt = stmt.where(RouteEvent.event_type == event_type.upper())
    stmt = stmt.order_by(RouteEvent.timestamp.desc()).limit(limit)
    events = (await db.execute(stmt)).scalars().all()
    return events


@router.get("/routes", response_model=List[BGPRouteResponse])
async def list_bgp_routes(
    prefix: Optional[str] = Query(None),
    peer_ip: Optional[str] = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns live BGP Route Visibility Table from database (populated via BMP / initial seed).
    All items are explicitly labeled with data_source ('live', 'lab', or 'simulated').
    """
    stmt = select(BGPRoute)
    if active_only:
        stmt = stmt.where(BGPRoute.is_active == True)
    if prefix:
        stmt = stmt.where(BGPRoute.prefix.ilike(f"%{prefix}%"))
    if peer_ip:
        stmt = stmt.where(BGPRoute.peer_ip == peer_ip)
    stmt = stmt.order_by(BGPRoute.last_updated.desc()).limit(limit)
    routes = (await db.execute(stmt)).scalars().all()

    # If database has no routes yet, provide default fallback routes
    if not routes:
        now = datetime.now(timezone.utc)
        default_seed_routes = [
            BGPRoute(
                prefix="1.1.1.0/24",
                peer_ip="198.51.100.1",
                peer_asn=7713,
                best_path="AS13335 (Cloudflare Transit)",
                next_hop="198.51.100.1",
                as_path="7713 13335",
                origin="IGP",
                communities="7713:100, 7713:200",
                data_source="simulated",
                is_active=True,
                last_updated=now,
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                peer_ip="198.51.100.5",
                peer_asn=4761,
                best_path="AS15169 (Google Transit)",
                next_hop="198.51.100.5",
                as_path="4761 15169",
                origin="IGP",
                communities="4761:300",
                data_source="simulated",
                is_active=True,
                last_updated=now,
            ),
            BGPRoute(
                prefix="208.67.222.0/24",
                peer_ip="198.51.100.1",
                peer_asn=7713,
                best_path="AS36692 (OpenDNS)",
                next_hop="198.51.100.1",
                as_path="7713 36692",
                origin="IGP",
                communities="7713:100",
                data_source="simulated",
                is_active=True,
                last_updated=now,
            ),
        ]
        db.add_all(default_seed_routes)
        await db.commit()
        for r in default_seed_routes:
            await db.refresh(r)
        if prefix:
            return [r for r in default_seed_routes if prefix in r.prefix]
        return default_seed_routes

    return routes


@router.get("/bmp/status", response_model=BMPStatusResponse)
async def get_bmp_status(
    current_user: User = Depends(get_current_user),
):
    """Returns BMP adapter operational metrics, socket listener status, and message counters."""
    return bmp_adapter_service.get_status()


@router.post("/bmp/simulate")
async def simulate_bmp_packet(
    payload: BMPSimulateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Synthesizes and processes a valid binary RFC 7854 BMP packet into the platform engine.
    Used for lab testing and verification without attaching a physical router.
    """
    m_type = payload.message_type.lower()
    source_label = "lab"

    if m_type == "initiation":
        raw_frame = build_bmp_initiation(sys_name="lab-mx480-core01", sys_descr="Junos 22.4R1 Lab Feed")
    elif m_type == "peer_up":
        raw_frame = build_bmp_peer_up(peer_ip=payload.peer_ip, peer_asn=payload.peer_asn)
    elif m_type == "peer_down":
        raw_frame = build_bmp_peer_down(peer_ip=payload.peer_ip, peer_asn=payload.peer_asn, reason=1)
    elif m_type == "route_monitoring":
        pfx = payload.prefix or "1.1.1.0/24"
        nh = payload.next_hop or payload.peer_ip
        asns = [payload.peer_asn, 13335]
        if payload.is_withdraw:
            raw_frame = build_bmp_route_monitoring(
                peer_ip=payload.peer_ip,
                peer_asn=payload.peer_asn,
                withdrawn_prefixes=[pfx],
                next_hop=nh,
            )
        else:
            raw_frame = build_bmp_route_monitoring(
                peer_ip=payload.peer_ip,
                peer_asn=payload.peer_asn,
                announced_prefixes=[pfx],
                next_hop=nh,
                as_path_asns=asns,
                communities=[(payload.peer_asn, 100)],
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown BMP simulation message type '{payload.message_type}'. Supported: initiation, peer_up, peer_down, route_monitoring.",
        )

    # Process frame through live ingestion pipeline
    res = await bmp_adapter_service.process_binary_frame(raw_frame, db, source_label=source_label)

    await record_audit_event(
        db=db,
        user=current_user,
        action="SIMULATE_BMP_MESSAGE",
        resource_type="bmp_adapter",
        resource_id=payload.peer_ip,
        details=f"Simulated BMP {payload.message_type} for peer {payload.peer_ip} (AS{payload.peer_asn}).",
        request=request,
    )

    return {
        "status": "success",
        "message": f"BMP {payload.message_type} frame ({len(raw_frame)} bytes) processed successfully.",
        "peer_ip": payload.peer_ip,
        "peer_asn": payload.peer_asn,
        "data_source": source_label,
    }


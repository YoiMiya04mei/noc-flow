"""BMP (BGP Monitoring Protocol - RFC 7854) Network Adapter & Ingestion Service

Provides:
- Non-blocking asyncio TCP server listening for RFC 7854 BMP feeds from routers
- Frame slicing, buffer bounds enforcement, and malformed frame protection
- Normalization into BGPPeer, BGPRoute, and RouteEvent database records
- Observability metrics (connections, messages, errors, peer state transitions)
- Graceful shutdown lifecycle management
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.bgp import BGPPeer, RouteEvent, BGPRoute
from app.services.bmp_parser import (
    parse_bmp_message,
    BMPParseError,
    BMPCommonHeader,
    parse_common_header,
    BMPInitiationMessage,
    BMPPeerUpMessage,
    BMPPeerDownMessage,
    BMPRouteMonitoringMessage,
    BMPTerminationMessage,
    BMP_COMMON_HEADER_LEN,
)

logger = logging.getLogger("jdp_platform.bmp")


class BMPAdapterService:
    """Carrier-grade BMP TCP listener and route event ingestion service."""

    def __init__(self):
        self._server: Optional[asyncio.Server] = None
        self._is_running: bool = False
        self._clients: Set[asyncio.StreamWriter] = set()
        self._lock = asyncio.Lock()

        # Telemetry metrics
        self._total_messages_received: int = 0
        self._total_parse_errors: int = 0
        self._total_route_events: int = 0
        self._total_peer_updates: int = 0
        self._last_message_at: Optional[datetime] = None
        self._supported_types: List[str] = [
            "Route Monitoring (Type 0)",
            "Peer Down Notification (Type 2)",
            "Peer Up Notification (Type 3)",
            "Initiation (Type 4)",
            "Termination (Type 5)",
        ]

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Returns current BMP adapter health, socket state, and ingestion metrics."""
        return {
            "is_running": self._is_running,
            "host": settings.BMP_HOST,
            "port": settings.BMP_PORT,
            "enabled": settings.BMP_ENABLED,
            "active_connections": len(self._clients),
            "total_messages_received": self._total_messages_received,
            "total_parse_errors": self._total_parse_errors,
            "total_route_events": self._total_route_events,
            "total_peer_updates": self._total_peer_updates,
            "last_message_at": self._last_message_at,
            "supported_message_types": self._supported_types,
            "lab_mode": settings.BGP_LAB_MODE,
        }

    async def start(self) -> None:
        """Starts the BMP TCP listener if enabled in settings."""
        if not settings.BMP_ENABLED:
            logger.info("BMP Adapter is disabled via configuration (BMP_ENABLED=False).")
            return

        async with self._lock:
            if self._is_running:
                return

            try:
                self._server = await asyncio.start_server(
                    self._handle_client_connection,
                    host=settings.BMP_HOST,
                    port=settings.BMP_PORT,
                )
                self._is_running = True
                logger.info(
                    "BMP Adapter TCP listener active on %s:%d (RFC 7854)",
                    settings.BMP_HOST,
                    settings.BMP_PORT,
                )
            except Exception as e:
                logger.error("Failed to bind BMP TCP listener on %s:%d: %s", settings.BMP_HOST, settings.BMP_PORT, e)
                self._is_running = False

    async def stop(self) -> None:
        """Gracefully closes all connected BMP router sessions and stops TCP listener."""
        async with self._lock:
            if not self._is_running:
                return

            logger.info("Stopping BMP Adapter listener and disconnecting active clients...")
            self._is_running = False

            # Disconnect active client streams
            for writer in list(self._clients):
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            self._clients.clear()

            if self._server:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
            logger.info("BMP Adapter shut down cleanly.")

    async def _handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles an individual router BMP TCP stream with streaming frame buffering."""
        peer_addr = writer.get_extra_info("peername")
        client_ip = peer_addr[0] if peer_addr else "unknown"

        # Check peer allowlist if configured
        if settings.BMP_ALLOWED_HOSTS and client_ip not in settings.BMP_ALLOWED_HOSTS:
            logger.warning("Rejecting BMP connection from unallowed host: %s", client_ip)
            writer.close()
            await writer.wait_closed()
            return

        self._clients.add(writer)
        logger.info("BMP Router connected from %s", client_ip)

        buffer = bytearray()
        try:
            while self._is_running:
                chunk = await reader.read(8192)
                if not chunk:
                    break

                buffer.extend(chunk)

                # Process complete frames from buffer
                while len(buffer) >= BMP_COMMON_HEADER_LEN:
                    try:
                        hdr = parse_common_header(bytes(buffer[:BMP_COMMON_HEADER_LEN]))
                    except BMPParseError as pe:
                        # Malformed header sync: discard 1 byte and scan for alignment
                        self._total_parse_errors += 1
                        logger.warning("BMP framing sync error from %s: %s", client_ip, pe)
                        buffer.pop(0)
                        continue

                    # Guard against excessive message length
                    if hdr.msg_length > settings.BMP_MAX_MESSAGE_SIZE:
                        self._total_parse_errors += 1
                        logger.error(
                            "BMP frame size %d exceeds limit %d from %s; resetting stream",
                            hdr.msg_length,
                            settings.BMP_MAX_MESSAGE_SIZE,
                            client_ip,
                        )
                        buffer.clear()
                        break

                    # Wait until full frame is buffered
                    if len(buffer) < hdr.msg_length:
                        break

                    # Extract single frame
                    frame = bytes(buffer[: hdr.msg_length])
                    buffer = buffer[hdr.msg_length :]

                    # Process frame in isolated database transaction
                    source_label = "lab" if settings.BGP_LAB_MODE else "live"
                    async with AsyncSessionLocal() as db:
                        await self.process_binary_frame(frame, db, source_label=source_label)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            logger.info("BMP client %s disconnected", client_ip)
        except Exception as e:
            logger.error("Unexpected error handling BMP client %s: %s", client_ip, e)
        finally:
            self._clients.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def process_binary_frame(
        self, frame: bytes, db: AsyncSession, source_label: str = "live"
    ) -> Optional[Any]:
        """
        Parses and stores an RFC 7854 BMP binary frame into PostgreSQL database.
        Safe to call from TCP stream or test/demo simulators.
        """
        try:
            msg = parse_bmp_message(frame)
            self._total_messages_received += 1
            self._last_message_at = datetime.now(timezone.utc)
        except BMPParseError as e:
            self._total_parse_errors += 1
            logger.warning("BMP parse failure: %s", e)
            return None
        except Exception as e:
            self._total_parse_errors += 1
            logger.error("Unexpected error parsing BMP frame: %s", e)
            return None

        # Handle parsed message types
        if isinstance(msg, BMPInitiationMessage):
            logger.info(
                "BMP Initiation received: sysName='%s', sysDescr='%s'",
                msg.sys_name,
                msg.sys_descr,
            )
            return msg

        elif isinstance(msg, BMPPeerUpMessage):
            await self._handle_peer_up(msg, db, source_label)
            return msg

        elif isinstance(msg, BMPPeerDownMessage):
            await self._handle_peer_down(msg, db, source_label)
            return msg

        elif isinstance(msg, BMPRouteMonitoringMessage):
            await self._handle_route_monitoring(msg, db, source_label)
            return msg

        elif isinstance(msg, BMPTerminationMessage):
            logger.info("BMP Termination received: reason='%s' (%s)", msg.reason_text, msg.description)
            return msg

        return msg

    async def _handle_peer_up(
        self, msg: BMPPeerUpMessage, db: AsyncSession, source_label: str
    ) -> None:
        """Handles BMP Peer Up event: upserts BGPPeer and creates audit RouteEvent."""
        peer = msg.peer
        now = datetime.now(timezone.utc)

        # Upsert BGPPeer
        stmt = select(BGPPeer).where(BGPPeer.peer_ip == peer.peer_ip)
        res = await db.execute(stmt)
        bgp_peer = res.scalar_one_or_none()

        if bgp_peer:
            bgp_peer.state = "Established"
            bgp_peer.remote_as = peer.peer_asn
            bgp_peer.router_id = peer.peer_bgp_id
            bgp_peer.last_error = None
            bgp_peer.data_source = source_label
            bgp_peer.last_change_at = now
        else:
            bgp_peer = BGPPeer(
                peer_ip=peer.peer_ip,
                local_as=136052,
                remote_as=peer.peer_asn,
                peer_name=f"Peer AS{peer.peer_asn}",
                state="Established",
                uptime_seconds=0,
                prefixes_received=0,
                prefixes_advertised=0,
                router_id=peer.peer_bgp_id,
                data_source=source_label,
                last_change_at=now,
            )
            db.add(bgp_peer)

        # Record RouteEvent
        event = RouteEvent(
            peer_ip=peer.peer_ip,
            event_type="STATE_CHANGE",
            prefix="0.0.0.0/0",
            as_path=f"AS{peer.peer_asn}",
            next_hop=peer.peer_ip,
            data_source=source_label,
            timestamp=now,
        )
        db.add(event)
        await db.commit()

        self._total_peer_updates += 1
        self._total_route_events += 1
        logger.info("BGP Peer Up recorded: %s (AS%d)", peer.peer_ip, peer.peer_asn)

    async def _handle_peer_down(
        self, msg: BMPPeerDownMessage, db: AsyncSession, source_label: str
    ) -> None:
        """Handles BMP Peer Down event: updates BGPPeer state and logs reason."""
        peer = msg.peer
        now = datetime.now(timezone.utc)

        stmt = select(BGPPeer).where(BGPPeer.peer_ip == peer.peer_ip)
        res = await db.execute(stmt)
        bgp_peer = res.scalar_one_or_none()

        if bgp_peer:
            bgp_peer.state = "Idle"
            bgp_peer.last_error = msg.reason_text
            bgp_peer.data_source = source_label
            bgp_peer.last_change_at = now

        event = RouteEvent(
            peer_ip=peer.peer_ip,
            event_type="STATE_CHANGE",
            prefix="0.0.0.0/0",
            as_path=f"AS{peer.peer_asn}",
            next_hop=peer.peer_ip,
            communities=f"DOWN:{msg.reason}",
            data_source=source_label,
            timestamp=now,
        )
        db.add(event)
        await db.commit()

        self._total_peer_updates += 1
        self._total_route_events += 1
        logger.warning("BGP Peer Down recorded: %s (AS%d) - Reason: %s", peer.peer_ip, peer.peer_asn, msg.reason_text)

    async def _handle_route_monitoring(
        self, msg: BMPRouteMonitoringMessage, db: AsyncSession, source_label: str
    ) -> None:
        """Handles BMP Route Monitoring event: updates BGPRoute and appends RouteEvent."""
        peer = msg.peer
        now = datetime.now(timezone.utc)
        events_to_add: List[RouteEvent] = []

        # 1. Process announced routes
        for item in msg.announced_routes:
            # Upsert into bgp_routes
            stmt = select(BGPRoute).where(
                BGPRoute.prefix == item.prefix,
                BGPRoute.peer_ip == peer.peer_ip,
            )
            res = await db.execute(stmt)
            route = res.scalar_one_or_none()

            best_path_label = f"AS{peer.peer_asn} ({item.as_path or 'Direct'})"
            if route:
                route.next_hop = item.next_hop
                route.as_path = item.as_path
                route.origin = item.origin
                route.med = item.med
                route.local_pref = item.local_pref
                route.communities = item.communities
                route.best_path = best_path_label
                route.is_active = True
                route.data_source = source_label
                route.last_updated = now
            else:
                route = BGPRoute(
                    prefix=item.prefix,
                    peer_ip=peer.peer_ip,
                    peer_asn=peer.peer_asn,
                    best_path=best_path_label,
                    next_hop=item.next_hop,
                    as_path=item.as_path,
                    origin=item.origin,
                    med=item.med,
                    local_pref=item.local_pref,
                    communities=item.communities,
                    data_source=source_label,
                    is_active=True,
                    last_updated=now,
                )
                db.add(route)

            events_to_add.append(
                RouteEvent(
                    peer_ip=peer.peer_ip,
                    event_type="ANNOUNCE",
                    prefix=item.prefix,
                    as_path=item.as_path,
                    next_hop=item.next_hop,
                    communities=item.communities,
                    data_source=source_label,
                    timestamp=now,
                )
            )

        # 2. Process withdrawn routes
        for w_prefix in msg.withdrawn_routes:
            # Mark route inactive
            await db.execute(
                update(BGPRoute)
                .where(BGPRoute.prefix == w_prefix, BGPRoute.peer_ip == peer.peer_ip)
                .values(is_active=False, last_updated=now)
            )
            events_to_add.append(
                RouteEvent(
                    peer_ip=peer.peer_ip,
                    event_type="WITHDRAW",
                    prefix=w_prefix,
                    data_source=source_label,
                    timestamp=now,
                )
            )

        # Increment peer prefix count
        if msg.announced_routes or msg.withdrawn_routes:
            p_stmt = select(BGPPeer).where(BGPPeer.peer_ip == peer.peer_ip)
            p_res = await db.execute(p_stmt)
            bgp_peer = p_res.scalar_one_or_none()
            if bgp_peer:
                delta = len(msg.announced_routes) - len(msg.withdrawn_routes)
                bgp_peer.prefixes_received = max(0, bgp_peer.prefixes_received + delta)

        if events_to_add:
            db.add_all(events_to_add)
            self._total_route_events += len(events_to_add)

        await db.commit()


# Global Singleton BMP Adapter Service
bmp_adapter_service = BMPAdapterService()

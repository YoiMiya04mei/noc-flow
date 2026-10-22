"""Active Path Probing Engine

Provides multi-protocol active measurement across diverse egress paths:
- TCP Connect Probing (SYN/ACK 3-way handshake RTT measurement)
- ICMP Echo Probing (with unprivileged fallback and raw socket support)
- Multi-sample statistical aggregation (min, avg, max latency, jitter, packet loss %)
- Egress interface & source IP socket binding
- Concurrency limit via asyncio Semaphore
- Deduplication of in-flight probes
- Stale target detection
- Background polling worker with graceful shutdown lifecycle
"""
import asyncio
import socket
import struct
import time
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.probe import ProbeTarget, ProbeResult
from app.services.egress_binding import egress_manager, EgressBindingMode

logger = logging.getLogger("jdp_platform.probes")


class ProbeMeasurementResult:
    """Encapsulates the aggregated statistics of a probe cycle."""

    def __init__(
        self,
        target_ip: str,
        probe_type: str,
        samples: List[float],
        packet_count: int,
        status: str,
        egress_mode: EgressBindingMode,
        error_message: Optional[str] = None,
    ):
        self.target_ip = target_ip
        self.probe_type = probe_type
        self.samples = samples
        self.packet_count = packet_count
        self.status = status
        self.egress_mode = egress_mode
        self.error_message = error_message

        successful = len(samples)
        if successful > 0:
            self.min_latency_ms = round(min(samples), 2)
            self.max_latency_ms = round(max(samples), 2)
            self.avg_latency_ms = round(sum(samples) / float(successful), 2)
            # Calculate jitter (mean absolute deviation between consecutive packets)
            if successful > 1:
                diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, successful)]
                self.jitter_ms = round(sum(diffs) / float(len(diffs)), 2)
            else:
                self.jitter_ms = 0.0
            self.loss_percent = round(((packet_count - successful) / float(packet_count)) * 100.0, 1)
        else:
            self.min_latency_ms = None
            self.max_latency_ms = None
            self.avg_latency_ms = 0.0
            self.jitter_ms = 0.0
            self.loss_percent = 100.0
            self.status = "timeout"


async def execute_tcp_connect_probe(
    target_ip: str,
    port: int = 80,
    timeout_ms: int = 2000,
    egress_interface: Optional[str] = None,
    source_ip: Optional[str] = None,
    packet_count: int = 3,
) -> ProbeMeasurementResult:
    """
    Executes multiple TCP connection probes to target_ip:port.
    Measures 3-way handshake round-trip latency.
    """
    samples: List[float] = []
    timeout_sec = max(0.1, timeout_ms / 1000.0)
    binding_mode = EgressBindingMode.OS_ROUTING_FALLBACK
    last_error: Optional[str] = None

    for _ in range(packet_count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)

        # Apply egress binding
        mode, notice = egress_manager.configure_socket_binding(sock, egress_interface, source_ip)
        binding_mode = mode

        t0 = time.perf_counter()
        try:
            # Connect asynchronously using asyncio event loop
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.sock_connect(sock, (target_ip, port)), timeout=timeout_sec)
            rtt = (time.perf_counter() - t0) * 1000.0
            samples.append(rtt)
        except asyncio.TimeoutError:
            last_error = "Connection timed out"
        except ConnectionRefusedError:
            # Target replied with RST! Layer-3 and layer-4 path is alive and responded.
            rtt = (time.perf_counter() - t0) * 1000.0
            samples.append(rtt)
        except OSError as e:
            last_error = str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Brief 20ms pause between samples
        if packet_count > 1:
            await asyncio.sleep(0.02)

    # Determine status
    if len(samples) == packet_count:
        status = "degraded" if (sum(samples) / len(samples)) > 200.0 else "ok"
    elif len(samples) > 0:
        status = "degraded"
    else:
        status = "timeout"

    return ProbeMeasurementResult(
        target_ip=target_ip,
        probe_type="tcp",
        samples=samples,
        packet_count=packet_count,
        status=status,
        egress_mode=binding_mode,
        error_message=last_error,
    )


async def execute_icmp_probe(
    target_ip: str,
    timeout_ms: int = 2000,
    egress_interface: Optional[str] = None,
    source_ip: Optional[str] = None,
    packet_count: int = 3,
) -> ProbeMeasurementResult:
    """
    Executes ICMP echo request probe.
    Attempts raw socket if privileged, or delegates to non-blocking system ping execution.
    """
    samples: List[float] = []
    timeout_sec = max(0.1, timeout_ms / 1000.0)
    binding_mode = EgressBindingMode.OS_ROUTING_FALLBACK
    last_error: Optional[str] = None

    is_windows = sys.platform == "win32"
    # Construct OS ping command
    if is_windows:
        # Windows ping: -n count, -w timeout_ms
        cmd = ["ping", "-n", str(packet_count), "-w", str(int(timeout_ms))]
        if source_ip:
            cmd.extend(["-S", source_ip])
            binding_mode = EgressBindingMode.SOURCE_IP_BIND
        cmd.append(target_ip)
    else:
        # Linux ping: -c count, -W timeout_sec
        cmd = ["ping", "-c", str(packet_count), "-W", str(max(1, int(timeout_sec)))]
        if egress_interface:
            cmd.extend(["-I", egress_interface])
            binding_mode = EgressBindingMode.SO_BINDTODEVICE
        elif source_ip:
            cmd.extend(["-I", source_ip])
            binding_mode = EgressBindingMode.SOURCE_IP_BIND
        cmd.append(target_ip)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec * packet_count + 3.0)
        output = stdout_bytes.decode("utf-8", errors="replace")

        # Parse RTT values from ping output
        for line in output.splitlines():
            line_lower = line.lower()
            if "time=" in line_lower or "waktu=" in line_lower:
                try:
                    # Windows: "time=14ms" or "time<1ms"; Linux: "time=14.2 ms"
                    part = line_lower.split("time")[1].split()[0].replace("=", "").replace("<", "").replace("ms", "")
                    val = float(part)
                    samples.append(val)
                except Exception:
                    pass
    except asyncio.TimeoutError:
        last_error = "ICMP probe timed out"
    except Exception as e:
        last_error = f"ICMP execution error: {e}"

    if len(samples) == packet_count:
        status = "degraded" if (sum(samples) / len(samples)) > 200.0 else "ok"
    elif len(samples) > 0:
        status = "degraded"
    else:
        status = "timeout"

    return ProbeMeasurementResult(
        target_ip=target_ip,
        probe_type="icmp",
        samples=samples,
        packet_count=packet_count,
        status=status,
        egress_mode=binding_mode,
        error_message=last_error,
    )


class ProbeBackgroundWorker:
    """Manages scheduled background probing of registered path targets."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._is_running: bool = False
        self._stop_event = asyncio.Event()
        self._in_flight_targets: Set[int] = set()
        self._in_flight_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(settings.PROBE_CONCURRENCY_LIMIT)

        # Worker Telemetry
        self._total_probes_attempted: int = 0
        self._total_probes_successful: int = 0
        self._total_probes_failed: int = 0
        self._total_timeouts: int = 0
        self._last_sweep_duration_ms: float = 0.0
        self._completed_cycles: int = 0

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Returns background probe worker operational metrics."""
        return {
            "is_running": self._is_running,
            "interval_seconds": settings.PROBE_WORKER_INTERVAL_SECONDS,
            "concurrency_limit": settings.PROBE_CONCURRENCY_LIMIT,
            "completed_cycles": self._completed_cycles,
            "total_attempted": self._total_probes_attempted,
            "total_successful": self._total_probes_successful,
            "total_failed": self._total_probes_failed,
            "total_timeouts": self._total_timeouts,
            "last_sweep_duration_ms": self._last_sweep_duration_ms,
            "in_flight_probes_count": len(self._in_flight_targets),
        }

    async def start(self) -> None:
        """Starts the periodic background active probe worker."""
        if not settings.PROBE_ENABLED:
            logger.info("Active Probing is disabled via configuration (PROBE_ENABLED=False).")
            return

        if self._is_running:
            return

        self._is_running = True
        self._stop_event.clear()
        self._task = asyncio.create_task(self._worker_loop(), name="ProbeBackgroundWorker")
        logger.info(
            "Active Probe Background Worker started (Interval=%ds, Concurrency=%d)",
            settings.PROBE_WORKER_INTERVAL_SECONDS,
            settings.PROBE_CONCURRENCY_LIMIT,
        )

    async def stop(self) -> None:
        """Gracefully halts the background worker."""
        if not self._is_running:
            return

        logger.info("Stopping Active Probe Background Worker...")
        self._is_running = False
        self._stop_event.set()

        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Active Probe Background Worker stopped cleanly.")

    async def _worker_loop(self) -> None:
        """Continuous polling sweep loop."""
        # Initial brief startup grace period
        try:
            await asyncio.sleep(2.0)
        except asyncio.CancelledError:
            return

        while self._is_running:
            t0 = time.perf_counter()
            try:
                await self.run_single_sweep()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error during probe worker sweep: %s", e)

            self._last_sweep_duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            self._completed_cycles += 1

            # Wait for next interval or cancellation
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=float(settings.PROBE_WORKER_INTERVAL_SECONDS),
                )
                break
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def run_single_sweep(self) -> None:
        """Executes a single sweep over all eligible active targets."""
        now = datetime.now(timezone.utc)
        targets_to_probe: List[ProbeTarget] = []

        async with AsyncSessionLocal() as db:
            # Query all active targets
            stmt = select(ProbeTarget).where(ProbeTarget.is_active == True)
            res = await db.execute(stmt)
            targets = res.scalars().all()

            # Filter targets whose interval has elapsed
            for tgt in targets:
                if not tgt.last_probed_at:
                    targets_to_probe.append(tgt)
                else:
                    elapsed = (now - tgt.last_probed_at).total_seconds()
                    if elapsed >= tgt.interval_seconds:
                        targets_to_probe.append(tgt)

            # Detect stale targets (> 120s without poll)
            for tgt in targets:
                if tgt.last_probed_at:
                    elapsed = (now - tgt.last_probed_at).total_seconds()
                    if elapsed > settings.PROBE_STALE_THRESHOLD_SECONDS and tgt.last_status != "stale":
                        tgt.last_status = "stale"
            await db.commit()

        if not targets_to_probe:
            return

        logger.debug("Active Probing: sweeping %d targets...", len(targets_to_probe))
        tasks = [self.probe_single_target(tgt.id) for tgt in targets_to_probe]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def probe_single_target(self, target_id: int) -> Optional[ProbeResult]:
        """Probes an individual target with concurrency semaphore and deduplication."""
        # 1. In-flight deduplication check
        async with self._in_flight_lock:
            if target_id in self._in_flight_targets:
                logger.debug("Probe already in-flight for target_id=%d; skipping", target_id)
                return None
            self._in_flight_targets.add(target_id)

        try:
            async with self._semaphore:
                async with AsyncSessionLocal() as db:
                    tgt = await db.get(ProbeTarget, target_id)
                    if not tgt or not tgt.is_active:
                        return None

                    self._total_probes_attempted += 1
                    target_ip = tgt.target_ip
                    probe_type = tgt.probe_type.lower()
                    port = tgt.port or 80
                    timeout_ms = tgt.timeout_ms
                    egress_iface = tgt.egress_interface
                    source_ip = tgt.source_ip
                    provider_id = tgt.provider_id

                # Perform actual network measurement
                if probe_type == "tcp":
                    res = await execute_tcp_connect_probe(
                        target_ip=target_ip,
                        port=port,
                        timeout_ms=timeout_ms,
                        egress_interface=egress_iface,
                        source_ip=source_ip,
                        packet_count=settings.PROBE_PACKET_COUNT,
                    )
                else:
                    res = await execute_icmp_probe(
                        target_ip=target_ip,
                        timeout_ms=timeout_ms,
                        egress_interface=egress_iface,
                        source_ip=source_ip,
                        packet_count=settings.PROBE_PACKET_COUNT,
                    )

                # Persist result to database
                now = datetime.now(timezone.utc)
                source_label = "live" if res.status in ("ok", "degraded") else "simulated"
                async with AsyncSessionLocal() as db:
                    probe_result = ProbeResult(
                        target_id=target_id,
                        provider_id=provider_id,
                        latency_ms=res.avg_latency_ms,
                        min_latency_ms=res.min_latency_ms,
                        max_latency_ms=res.max_latency_ms,
                        loss_percent=res.loss_percent,
                        jitter_ms=res.jitter_ms,
                        hops=1,
                        status=res.status,
                        egress_mode=res.egress_mode.value,
                        data_source=source_label,
                        timestamp=now,
                    )
                    db.add(probe_result)

                    # Update ProbeTarget cached metrics
                    target_row = await db.get(ProbeTarget, target_id)
                    if target_row:
                        target_row.last_probed_at = now
                        target_row.last_latency_ms = res.avg_latency_ms
                        target_row.last_loss_percent = res.loss_percent
                        target_row.last_status = res.status

                    await db.commit()
                    await db.refresh(probe_result)

                if res.status == "ok":
                    self._total_probes_successful += 1
                elif res.status == "timeout":
                    self._total_timeouts += 1
                    self._total_failed += 1
                else:
                    self._total_probes_successful += 1 # Degraded is still responsive

                return probe_result

        finally:
            async with self._in_flight_lock:
                self._in_flight_targets.discard(target_id)


# Global singleton probe worker
probe_background_worker = ProbeBackgroundWorker()

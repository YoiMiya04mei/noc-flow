# ADR 0005: Isolated BGP Lab Architecture and Automated Rollback Coordinator

## Status
Accepted

## Context
Automated routing optimization platforms must validate BGP route announcements, local preference changes, and withdrawals in a realistic, non-simulated BGP routing protocol environment before any change can be considered for production staging. However, connecting experimental route optimizers to live transit providers or company edge routers creates a catastrophic risk of BGP route leaks, hijacks, or traffic blackholing.

Phase 6 requires an isolated testbed that:
1. Runs real BGP speakers with standard BGP finite state machines (RFC 4271).
2. Proves that route announcements propagate to upstream peers and that withdrawals cleanly purge routes.
3. Automatically rolls back partial or failing changes using specific compensating operations.
4. Operates strictly in an isolated container network with zero routes to the corporate LAN or public Internet.
5. Keeps `ROUTING_EXECUTION_ENABLED=false` permanently locked.

## Decision

### 1. Technology Selection: GoBGP in Isolated Containers
We selected **GoBGP** (`osrg/gobgp:latest`) over FRRouting for the lab environment because:
- **Native Go / Container Compatibility**: Fully containerized, starts in < 2 seconds, minimal memory footprint (< 30 MB RAM per speaker).
- **Structured JSON & gRPC API**: Provides programmatic inspection of neighbors and Adj-RIB-In/Adj-RIB-Out via native CLI (`gobgp -j`) and gRPC without fragile vtysh terminal scraping.
- **Zero Kernel Netlink Pollution**: GoBGP can run in user-space without modifying host kernel routing tables.

### 2. Lab Topology & Isolation
- **Lab Speaker 1 (Sender / Edge)**:
  - ASN: `65001` (Private 2-byte ASN, distinct from production ASNs).
  - Router ID: `10.99.0.10`
  - Peer: `10.99.0.20` (Speaker 2), Remote ASN `65002`.
- **Lab Speaker 2 (Receiver / Upstream)**:
  - ASN: `65002` (Private 2-byte ASN).
  - Router ID: `10.99.0.20`
  - Peer: `10.99.0.10` (Speaker 1), Remote ASN `65001`.
- **Network Isolation**:
  - Connected via a dedicated Docker network `jdp-bgp-lab-net` configured with `internal: true`.
  - Docker does not configure a default gateway for `internal: true` networks, physically preventing outbound Internet routing or corporate intranet reachability.
  - Port 179/TCP is **NOT** published to the host network or any public IP. BGP traffic remains strictly inside the isolated bridge.

### 3. Execution Gateways & Safety Flags
- **`ROUTING_EXECUTION_ENABLED`**: Remains locked at `false`.
- **`BGP_LAB_ENABLED`**: New independent feature flag (default `false`). Lab execution is blocked unless this flag is explicitly enabled.
- **Prefix Allowlist for Lab**:
  - Only RFC 1918 / RFC 5737 test prefixes configured in `BGP_LAB_ALLOWED_PREFIXES` (e.g., `10.100.1.0/24`, `10.100.2.0/24`, `10.200.0.0/24`) are accepted.
  - Default routes (`0.0.0.0/0`, `::/0`) and unapproved prefixes are rejected with `HTTP 400 Bad Request`.

### 4. Automated Rollback Coordinator
- **Pre-check**: 11-point inspection verifies speaker health, Established peer session, allowlist compliance, and absence of concurrent changes before any route mutation.
- **Compensating Action**:
  - Failed Announce -> Specific withdrawal of announced prefix.
  - Failed Withdrawal -> Specific re-announcement of prior route snapshot.
- **Verification**: Rollback success is verified against the receiver's actual Adj-RIB-In.
- **Terminal States**: `ROLLBACK_SUCCEEDED`, `ROLLBACK_FAILED`, or `NEEDS_MANUAL_REVIEW`.

## Consequences
- **Positive**:
  - Validates full BGP update / withdrawal lifecycle on actual BGP speaker software without physical routers.
  - Guaranteed zero-leakage into production networks.
  - Complete pre/post-check audit trail attached to Change Requests.
- **Negative / Trade-offs**:
  - Requires Docker daemon with container execution privileges to run live speaker containers.
  - Integration tests must handle graceful fallback (`SKIPPED` or `BLOCKED` with clear logging) when Docker is unavailable.

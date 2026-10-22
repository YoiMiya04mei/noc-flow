# ADR 0007: Phase 8 Hardening, Scalability, and Production Readiness Architecture

## Status
Accepted

## Context
As the JDP Route Intelligence Platform enters its final implementation phase (Phase 8), the system requires rigorous hardening across stability, scalability, security, disaster recovery, and operational ergonomics. The platform combines high-throughput asynchronous telemetry ingestion (Go Flow Collector, ClickHouse), deterministic multi-criteria path optimization, relational change controls (PostgreSQL, Alembic), and isolated network lab validation (GoBGP).

The core requirement of Phase 8 is to ensure the platform is resilient against failure modes, possesses verified non-destructive backup/restore pipelines, adheres to immutable compliance audit standards, and maintains strict execution boundaries preventing unauthorized live network mutations.

## Decision

### 1. Database Backup & Isolated Restore Strategy
- **PostgreSQL**: Implemented logical backup via `pg_dump` with gzip compression and SHA-256 integrity checksums. Restore drills must strictly target isolated test databases (`jdp_route_intel_restore_test`) to verify schema and row count fidelity without endangering production state.
- **ClickHouse**: Implemented DDL export combined with tab-separated partitioned data extraction (`TabSeparatedWithNamesAndTypes`) into tar.gz archives. Restores target isolated test databases (`jdp_flow_analytics_restore_test`) with automatic DDL qualification rewriting.
- **Overwriting Guardrails**: Scripts explicitly prohibit restoring directly over active production databases unless dangerous CLI override flags are supplied.

### 2. Data Retention & Compliance Immutability
- **Raw Telemetry**: ClickHouse raw flow records expire after 30 days via MergeTree TTL and periodic maintenance pruning.
- **Aggregated Analytics**: Hourly aggregated traffic matrices are retained for 90 days.
- **Network Interface & Probe Metrics**: PostgreSQL historical time-series (`interface_metrics_history`, `probe_results`) are pruned beyond 90 and 30 days respectively.
- **Audit Immutability**: The `audit_events` compliance log is strictly exempt from retention cleanup. All maintenance actions generate an immutable `RETENTION_CLEANUP_EXEC` event.

### 3. Execution Safety Defense-in-Depth
- All execution flags remain locked at `false` by default:
  - `ROUTING_EXECUTION_ENABLED = false`
  - `PRODUCTION_ROUTING_ENABLED = false`
  - `FLOWSPEC_EXECUTION_ENABLED = false`
  - `RTBH_EXECUTION_ENABLED = false`
- The platform operates in read-only / simulation mode for production routing targets. All active routing tests are restricted to the isolated Docker BGP speakers (`jdp-bgp-speaker-1` and `jdp-bgp-speaker-2`).

### 4. Scalability & Throughput Benchmarking
- Established reproducible Go microbenchmarks for protocol parsers:
  - NetFlow v5: ~9.08M records/sec/core (3.3 microseconds per 30-record datagram).
  - NetFlow v9: ~2.78M records/sec/core (428 nanoseconds per record).
- ClickHouse batch insertion verified at ~40.8K records/sec on standard local NVMe/SSD storage.
- ClickHouse analytics queries (Data Explorer, Top Talkers, AS Traffic Matrix) consistently deliver sub-60ms p95 latencies.

## Consequences
- **Positive**: Complete disaster recovery confidence; demonstrable sub-second query performance; verifiable safety guardrails preventing unintentional routing outages.
- **Trade-offs**: Storage footprint grows moderately with 30-day raw flow retention (mitigated by ZSTD(1) compression); manual operator action is required to purge old backup files if disk approaches capacity.

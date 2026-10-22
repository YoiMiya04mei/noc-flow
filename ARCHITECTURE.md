# Architecture Specification: JDP Route Intelligence Platform

## 1. High-Level Architectural Overview

JDP Route Intelligence Platform is engineered for carrier-grade network operations centers (NOC) and Internet Service Providers (ISP). The platform unites two high-impact domains:
1. **Flow & Telemetry Intelligence (NFA-Class)**: Scalable ingestion and multi-dimensional analysis of NetFlow, IPFIX, sFlow, SNMP, and interface telemetry.
2. **Routing Intelligence & BGP Optimization (IRP-Class)**: Autonomous quality probing, multi-homing route recommendations, policy simulation, and strictly guarded BGP change execution.

```
                    +-------------------------------------------------------------+
                    |                 Network Devices (Routers/Switches)          |
                    +-------------------------------------------------------------+
                           | NetFlow/IPFIX/sFlow (UDP)        | SNMP Poll / BGP
                           v                                  v
    +-----------------------------------------------+   +-----------------------------+
    |   Go High-Rate Flow Collector (collector/)    |   | SNMP Poller & Active Prober |
    |   - NetFlow v5/v9, IPFIX, sFlow Listeners     |   | - Latency / Loss / Jitter   |
    |   - Memory batching & normalization           |   | - Interface stats & Deltas  |
    +-----------------------------------------------+   +-----------------------------+
                           |                                           |
                           v (Batched Inserts)                         v
    +-----------------------------------------------+   +-----------------------------+
    |      ClickHouse (Analytical DB)               |   |     PostgreSQL 16 (App DB)  |
    | - Raw Flow Records (Ordered, Partitioned)     |   | - Users, Roles, RBAC        |
    | - Hourly / Daily Aggregated Views             |   | - Device Inventory & Peers  |
    | - Time-series top talkers & traffic matrices  |   | - Audit Log (Append-only)   |
    +-----------------------------------------------+   +-----------------------------+
                           ^                                           ^
                           |                                           |
                           +--------------------+----------------------+
                                                |
                                                v
                    +-------------------------------------------------------------+
                    |             FastAPI Backend Service (backend/)              |
                    | - REST API v1 (/api/v1)                                     |
                    | - JWT Auth & Role-Based Access Control (RBAC)               |
                    | - Recommendation Engine & Safety Guardrails                 |
                    | - Audit Logger & Event Dispatcher                           |
                    +-------------------------------------------------------------+
                           ^                                           |
                           | HTTP / JSON                               v Controlled API
                    +-------------------------+         +-----------------------------+
                    |  Next.js Frontend (web) |         |  Isolated BGP Lab (Lab Env) |
                    | - Dark NOC Theme        |         | - FRRouting / GoBGP         |
                    | - Data Explorer & Chart |         | - Route Injection / Rollback|
                    | - Guardrail Dashboards  |         | - Production Gated (OFF)    |
                    +-------------------------+         +-----------------------------+
```

---

## 2. Component Boundaries & Responsibilities

### 2.1 Go Flow Collector (`collector/`)
- **Language**: Go 1.23+
- **Purpose**: Low-latency, multi-core, non-blocking UDP ingestion service.
- **Supported Formats**: NetFlow v5, NetFlow v9 (template-based), IPFIX (RFC 7011), sFlow v5.
- **Normalization**: Decouples wire formats into a unified `FlowRecord` schema containing:
  - `timestamp`: UTC timestamp with millisecond precision.
  - `exporter_ip`: IP of exporting router/device.
  - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `tcp_flags`.
  - `packets`, `bytes`, `input_snmp`, `output_snmp`, `next_hop`, `sampling_rate`.
- **Fault-Tolerance**: Malformed datagrams increment `parse_errors` and log details without terminating the receiver.
- **Batching**: Buffered channel worker pool flushing to ClickHouse every 1000 records or 1 second.

### 2.2 Analytical Storage (`ClickHouse`)
- **Engine**: `MergeTree` family.
- **Partitioning**: Monthly `toYYYYMM(timestamp)` for rapid partition dropping during retention enforcement.
- **Sorting Key**: `(site_id, exporter_ip, protocol, timestamp)` for high query efficiency when filtering by NOC POP and exporter.
- **Aggregations**: Materialized views calculating bytes/packets per minute/hour for 95th-percentile billing and historical trend charts.

### 2.3 Application & Metadata Database (`PostgreSQL 16`)
- **Engine**: PostgreSQL with async SQLAlchemy and Alembic migrations.
- **Tables**:
  - `users`: Credentials (Argon2id/bcrypt hashed), email, active status, role.
  - `roles`: Role definitions and capabilities.
  - `sites`: POP/datacenter locations with bandwidth commitments.
  - `providers`: Upstream transit/peering providers, ASN, contracted capacity, unit cost weight.
  - `devices`: Core routers, edge routers, management IP, SNMP profile reference, status.
  - `interfaces`: Interface metadata, speed, alias, admin/oper status, ifIndex.
  - `bgp_peers`: Local/remote ASN, peer IP, AFI/SAFI, state, uptime, prefix limits.
  - `probe_targets`: IP targets, egress provider binding, probe interval, timeout.
  - `probe_results`: Latency (RTT ms), packet loss (%), jitter (ms), hops.
  - `recommendations`: Proposed route change, current path, alternate path, score delta, confidence, justification.
  - `change_requests`: Lifecycle (`draft`, `simulated`, `approved`, `applied`, `rolled_back`), requester, approver, diff payload.
  - `audit_events`: Immutable append-only log recording actor, action, entity, before/after snapshot, IP address.
  - `system_settings`: Feature flags (including `ROUTING_EXECUTION_ENABLED`).
  - `snmp_profiles`: Encrypted credentials at rest using **AES-128-CBC with HMAC-SHA256 (Fernet Specification RFC 0x80)**, keyed via SHA-256 derivation of `SECRET_KEY` (see [ADR 0008](file:///docs/adr/0008-cryptography-specification-and-aead-migration-plan.md)).

### 2.4 Application API Service (`backend/`)
- **Framework**: Python 3.12+ FastAPI, Pydantic v2.
- **Security**: JWT bearer token authentication, Argon2id password hashing, strict RBAC dependencies on every endpoint.
- **Data Query Orchestrator**: Bridges queries between ClickHouse (high-speed flow metrics) and PostgreSQL (device/site metadata).

### 2.5 Web Frontend (`frontend/`)
- **Framework**: **Next.js 16 Active LTS (App Router)**, React 19, TypeScript, Tailwind CSS.
- **Design System**: NOC Dark Mode default with high-contrast text and crisp data visualizations.
- **Status Transparency**: Every widget clearly displays data freshness and explicit badges:
  - `[DEMO DATA]` - generated by simulator for demonstration/training.
  - `[LAB/SIMULATED]` - derived from testbed or sandbox environment.
  - `[LIVE]` - genuine telemetry from monitored devices.

### 2.6 BGP Monitoring Protocol (BMP) Adapter (`backend/app/services/bmp_parser.py`)
- **Standard**: RFC 7854 BGP Monitoring Protocol over TCP port 11019.
- **Message Type Coverage** (see [ADR 0009](file:///docs/adr/0009-bmp-protocol-coverage-reconciliation.md)):
  - **Parsed & Operational**: Type 0 (Route Monitoring / BGP UPDATE), Type 2 (Peer Down), Type 3 (Peer Up), Type 4 (Initiation), Type 5 (Termination).
  - **Unsupported / Out of Scope**: Type 1 (Statistics Report), Type 6 (Route Mirroring) — safely rejected via `BMPParseError` without process crashes.
  - **Robustness**: Unit-tested against RFC binary wire-format fixtures with zero-crash guarantees on malformed/truncated streams.

---

## 3. Data Flow Pipelines

### Flow Ingestion Pipeline
```
[Router] --UDP:2055/6343--> [Collector UDP Listener]
                                    |
                                    v
                           [Queue Buffer (100K)]
                                    |
                         [Worker Pool (NumCPU)]
                                    | (Parse & Normalize)
                                    v
                            [Batch Accumulator]
                                    | (1000 items / 1s)
                                    v
                         [ClickHouse Native/HTTP]
```

### Routing Recommendation & Change Lifecycle
```
[Probes & Flow Telemetry] --> [FastAPI Recommendation Engine]
                                      |
                                      v
                             [Candidate Recommendation]
                                      |
                             [Policy Simulator (Dry-Run)]
                                      |
                             [Change Request Draft]
                                      |
                       [Peer/Prefix Allowlist Check]
                                      |
                     [Dual Approval (Approver Role)]
                                      |
                     +----------------+----------------+
                     |                                 |
           (Lab Enabled)                      (Production Gated)
                     v                                 v
        [Inject to Lab BGP Speaker]      [BLOCKED: ROUTING_EXECUTION_ENABLED=false]
                     |                                 |
           [Post-check Telemetry]                 [Audit Record]
                     |
         (Fail? -> Automatic Rollback)
```

---

## 4. Security & Safety Guardrails

1. **Deny-by-Default Routing**:
   - `0.0.0.0/0` and `::/0` (Default routes) can NEVER be announced by the engine.
   - Bogons, martians (RFC 1918, RFC 6598, RFC 3927) and unlisted prefixes are rejected at the Pydantic schema validation layer.
2. **Execution Gates & Production Lockdown**:
   - Four independent guardrail flags default to `false`:
     - `ROUTING_EXECUTION_ENABLED=false` (Master kill-switch for all live routing changes)
     - `PRODUCTION_ROUTING_ENABLED=false` (Restricts live execution to lab topology only)
     - `FLOWSPEC_EXECUTION_ENABLED=false` (Locks FlowSpec mitigation injection)
     - `RTBH_EXECUTION_ENABLED=false` (Locks Remotely Triggered Black Hole injection)
   - Evaluated by the 12-Point Backend Execution Gate. Any missing approval or disabled flag returns HTTP 403 Forbidden with `ERR_ROUTING_EXECUTION_DISABLED`.
3. **Audit Trail**:
   - An immutable PostgreSQL table (`audit_events`) records every configuration change, login event, password rotation, and approval action with actor identity and client IP.
4. **Secret Handling & Cryptography**:
   - SNMP community strings, BGP MD5 keys, and passwords are never included in API responses (serialized as `null` or `***`) and never logged to stdout/stderr.
   - Encrypted at rest via AES-128-CBC + HMAC-SHA256 (Fernet RFC 0x80) with zero plain-text leaks to disk or logs.

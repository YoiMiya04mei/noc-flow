# ADR 0002: Dual-Database Storage Architecture (ClickHouse and PostgreSQL)

## Status
Accepted

## Context
Network operations platforms produce two vastly different categories of data:
1. **Relational / Transactional Data (OLTP)**: Users, passwords, roles, ACLs, site inventories, router credentials, change approvals, and audit logs. Volume is relatively low (thousands to hundreds of thousands of records), but strict ACID compliance, relational foreign keys, and transaction rollbacks are non-negotiable.
2. **Time-Series Analytical Data (OLAP)**: NetFlow, IPFIX, and sFlow records. Volume is extremely high (millions to billions of events daily). Operations are append-only with heavy aggregation queries (e.g., sum bytes by source ASN and destination port over the last 24 hours).

Placing high-velocity flow records into PostgreSQL causes index bloat, vacuum contention, and slow analytical queries. Conversely, ClickHouse is not designed for relational transactions, row-level updates, or complex multi-table joins with foreign keys.

## Decision
We implement a dual-database architecture:
1. **PostgreSQL 16**:
   - Sole source of truth for application configuration, device inventory, authentication credentials, security policies, change management workflows, and audit events.
   - Managed via Alembic migrations.
2. **ClickHouse**:
   - Dedicated analytical engine for raw and aggregated flow telemetry.
   - Primary table `flow_records` partitioned monthly by `toYYYYMM(timestamp)` and ordered by `(site_id, exporter_ip, protocol, timestamp)`.
   - Materialized views for fast 1-minute and 1-hour rollups.
   - Raw flow data has a configurable Time-To-Live (TTL) (e.g., 30 days) after which ClickHouse automatically drops older partitions.

## Consequences
- **Positive**:
  - PostgreSQL remains lightweight, fast, and easy to back up with standard `pg_dump`.
  - ClickHouse delivers 10x-100x faster aggregation queries with high data compression rates (typically 4x-8x).
  - Clean separation of concerns between operational configuration and telemetry storage.
- **Negative / Trade-offs**:
  - Operators must maintain two database services.
  - Queries that correlate flow telemetry with router metadata must query ClickHouse for IPs/ports and resolve entity names in the application layer.

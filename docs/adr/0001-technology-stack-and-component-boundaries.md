# ADR 0001: Technology Stack and Component Boundaries

## Status
Accepted

## Context
The JDP Route Intelligence Platform requires ingesting high-throughput UDP network flow packets (tens of thousands of packets per second), running complex analytical queries on massive datasets, orchestrating routing policies with strict guardrails, and presenting real-time telemetry to network engineers through an intuitive web interface.

A monolithic single-language architecture would introduce severe bottlenecks:
- Python is ideal for rapid development of complex mathematical models, REST APIs, and database migrations, but the Global Interpreter Lock (GIL) and runtime overhead make it suboptimal for zero-drop multi-gigabit UDP packet ingestion.
- Pure Go is excellent for high-concurrency systems programming, but has a less mature ecosystem for data science, dynamic policy simulation, and complex ORM migrations compared to FastAPI/SQLAlchemy/Alembic.
- A pure relational database (PostgreSQL) quickly degrades under continuous millions of raw flow inserts per hour.

## Decision
We decouple the platform into specialized, loosely coupled services:
1. **Flow Ingestion**: Standalone Go service (`collector/`). Go handles UDP sockets, goroutine worker pools, zero-copy byte parsing, and batched ClickHouse inserts.
2. **Analytical Storage**: ClickHouse. Uses columnar storage, LZ4/ZSTD compression, and vector execution for sub-second aggregations over billions of flow records.
3. **Application API & Logic**: FastAPI (Python 3.12). Manages authentication, RBAC, CRUD operations, recommendation algorithms, simulation dry-runs, and audit logging.
4. **Application Metadata DB**: PostgreSQL 16. Handles relational integrity, transactions, and audit trails.
5. **Web Interface**: Next.js 14+ (TypeScript, Tailwind CSS). Responsive NOC dark-mode interface with accessible tables, interactive charts, and real-time status badges.

## Consequences
- **Positive**:
  - Predictable performance: Flow ingestion spikes cannot freeze or crash the web API.
  - Scale-out ready: The Go collector can be horizontally scaled across multiple machines without modifying backend logic.
  - Development velocity: FastAPI provides automatic OpenAPI documentation and strict type validation via Pydantic.
- **Negative / Trade-offs**:
  - Polyglot repository requiring Go and Python build toolchains (standardized via Docker Compose).
  - Inter-service networking must be handled gracefully with health checks and circuit breakers.

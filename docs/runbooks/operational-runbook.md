# JDP Route Intelligence Platform — Operational Runbook
**Document Version:** 1.0.0 (Phase 8 Production Readiness)  
**Target Audience:** NOC Operations, Network Reliability Engineers, System Administrators  

---

## 1. System Architecture & Network Boundaries

### Port and Protocol Allocation
| Service | Container | Internal Port | Host Published Port | Protocol | Purpose | Network Boundary |
|---|---|---|---|---|---|---|
| PostgreSQL | `jdp-postgres` | 5432 | 5433 | TCP | Application Relational DB | Internal Docker / Localhost |
| ClickHouse HTTP | `jdp-clickhouse` | 8123 | 8123 | TCP | Telemetry REST API | Internal Docker / Localhost |
| ClickHouse Native | `jdp-clickhouse` | 9000 | 9000 | TCP | High-speed binary ingestion | Internal Docker / Localhost |
| Go Flow Collector | `jdp-collector` | 2055 | 2055 | UDP | NetFlow v5/v9 Ingestion | Border Routers / Management VLAN |
| Go Flow Collector | `jdp-collector` | 6343 | 6343 | UDP | sFlow v5 Ingestion | Core Switches / Management VLAN |
| Go Flow Collector | `jdp-collector` | 4739 | 4739 | UDP | IPFIX Ingestion | Edge Routers / Management VLAN |
| BMP Listener | `jdp-backend` | 11019 | 11019 | TCP | RFC 7854 BMP Telemetry | BGP Route Reflectors |
| Backend API | `jdp-backend` | 8000 | 8000 | TCP | FastAPI REST & Docs | Reverse Proxy / Admin LAN |
| Frontend Web UI | `jdp-frontend` | 3000 | 3000 | TCP | Next.js Dashboard | Reverse Proxy / NOC Browser |
| BGP Lab Speaker 1 | `jdp-bgp-speaker-1` | 50051 | 50051 | TCP | GoBGP gRPC (Isolated Lab) | Loopback / Internal Docker |
| BGP Lab Speaker 2 | `jdp-bgp-speaker-2` | 50052 | 50052 | TCP | GoBGP gRPC (Isolated Lab) | Loopback / Internal Docker |

> [!CAUTION]
> Ports 5433, 8123, 9000, 50051, and 50052 MUST NOT be exposed to the public Internet. Bind strictly to localhost (`127.0.0.1`) or secure internal management subnets.

---

## 2. Installation & Cold Startup

### Prerequisites
- Docker Engine >= 24.0 & Docker Compose v2.
- Python 3.11+ (for administrative and backup scripts).
- Minimum Host Specs: 4 vCPU, 8 GB RAM, 50 GB SSD.

### Step-by-Step Clean Deployment
1. **Clone repository and configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env: Replace default passwords and verify POSTGRES_PORT=5433
   ```
2. **Launch Core Containers:**
   ```bash
   docker compose up -d postgres clickhouse
   ```
3. **Verify Database Health:**
   ```bash
   docker compose ps
   # Ensure jdp-postgres and jdp-clickhouse report 'healthy'
   ```
4. **Execute Database Migrations:**
   ```bash
   cd backend
   python -m alembic upgrade head
   cd ..
   ```
5. **Initialize Seed Data (Users, Providers, Default Guardrails):**
   ```bash
   python backend/seed.py
   python scripts/seed_clickhouse.py
   ```
6. **Launch Collector, Backend, and Frontend:**
   ```bash
   docker compose up -d
   ```
7. **Access Platform & Administrator Provisioning:**
   - Web UI: `http://localhost:3000`
   - API Docs: `http://localhost:8000/docs`
   - Administrator Provisioning: Run `python scripts/bootstrap_admin.py --username admin` to securely generate or set the super_admin password (or configure `INITIAL_ADMIN_PASSWORD` in `.env`). Do NOT use default or shared credentials.

---

## 3. Routine Operations & Daily Checklist

### Morning Shift Handover Checklist
1. **Check Dashboard Health Banners:**
   - Verify zero unhandled critical incidents on `/alerts`.
   - Verify Circuit Breaker status is `CLOSED`.
2. **Telemetry Freshness:**
   - Check SNMP poller last executed $< 60\text{ s}$ ago.
   - Check Active Path probes report $< 30\text{ s}$ freshness.
3. **Review Pending Recommendations:**
   - Navigate to `/optimization`.
   - Review proposed route changes. Validate:
     - Target prefix belongs to active prefix allowlist (`/settings`).
     - Composite score improvement $> 15\%$ hysteresis threshold.
     - Reason and metric breakdown (RTT delta, loss delta, capacity headroom).
4. **Change Request Approval Flow (Dual-Control):**
   - Engineer creates Change Request.
   - Separate Approver (`lead_approver` or Super Admin) reviews diff and signs off.
   - Anti-self-approval rule strictly prohibits engineer from self-authorizing.

---

## 4. Maintenance & Lifecycle Management

### Backup Schedule
- **Daily Automated Backup (PostgreSQL & ClickHouse):**
  ```bash
  python scripts/backup_postgres.py
  python scripts/backup_clickhouse.py
  ```
- **Weekly Isolated Restore Drill:**
  ```bash
  python scripts/run_backup_restore_drill.py
  ```

### Retention Maintenance Schedule
- **Bi-weekly Cleanup (Scheduled Cron):**
  ```bash
  # Dry-run inspection:
  python scripts/retention_maintenance.py
  # Execution:
  python scripts/retention_maintenance.py --execute
  ```

---

## 5. Security & Credential Rotation Procedures

### Password and Secret Key Rotation
1. Update `.env`:
   - `SECRET_KEY`: Generate a 64-character random hex string.
   - `POSTGRES_PASSWORD`: Update PostgreSQL credentials.
   - `CLICKHOUSE_PASSWORD`: Update ClickHouse credentials.
2. In PostgreSQL:
   ```sql
   ALTER USER jdp_user WITH PASSWORD 'NewStrongPassword2026!';
   ```
3. Restart backend service:
   ```bash
   docker compose restart backend
   ```
4. Confirm user logins and token validations.

---

## 6. Safety Policy Summary
- **Execution Gates:** All live physical router configuration pushes remain blocked by default in source code (`ROUTING_EXECUTION_ENABLED=false`).
- **Audit Immutability:** The `audit_events` table cannot be truncated by retention scripts and retains full compliance trails for all system actions.

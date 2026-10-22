# JDP Route Intelligence Platform — Disaster Recovery Runbook
**Document Version:** 1.0.0 (Phase 8 Hardening)  
**Classification:** Confidential — Internal NOC Operations  
**Safety Status:** Production Routing Execution Gated (`ROUTING_EXECUTION_ENABLED=false`)

---

## 1. Disaster Scenarios & Immediate Responses

### Scenario A: PostgreSQL Primary Database Outage
* **Symptoms:** Backend returns HTTP 500 / Database connection errors; workers unable to persist metrics; UI shows "Database connection error".
* **Impact:** Telemetry ingestion halts; configuration changes and approvals are blocked; existing router configurations remain untouched (zero routing flaps).
* **Automatic Safety Behavior:**
  * Circuit breaker prevents any new change request execution.
  * Audit logs remain intact on host storage.
* **Recovery Procedure:**
  1. Inspect container logs:
     ```bash
     docker logs --tail 100 jdp-postgres
     ```
  2. Verify container status and disk space:
     ```bash
     docker ps -a --filter name=jdp-postgres
     df -h
     ```
  3. Restart container if stopped:
     ```bash
     docker compose restart postgres
     ```
  4. If database data corrupted, execute disaster recovery restore drill from latest verified backup:
     ```bash
     python scripts/restore_postgres.py backups/postgres/<LATEST_BACKUP>.sql.gz --dangerously-overwrite-active-db
     ```
  5. Validate table counts and user authentication after recovery.

---

### Scenario B: ClickHouse Analytics Database Outage
* **Symptoms:** Dashboard charts show "ClickHouse disconnected - Showing demo/cached mode"; Flow Explorer queries return 503 or empty sets.
* **Impact:** Historical traffic trends unavailable; SNMP polling and BGP state monitoring continue operating normally; Flow collector buffers datagrams up to buffer limit.
* **Automatic Safety Behavior:**
  * `ClickHouseService` switches to safe fallback mode.
  * No application crash or silent data corruption.
* **Recovery Procedure:**
  1. Check ClickHouse container logs:
     ```bash
     docker logs --tail 100 jdp-clickhouse
     ```
  2. Restart ClickHouse service:
     ```bash
     docker compose restart clickhouse
     ```
  3. Verify HTTP ping on IPv4:
     ```bash
     docker exec jdp-clickhouse wget -q --spider http://127.0.0.1:8123/ping
     ```
  4. If volume corrupted, restore from latest verified archive:
     ```bash
     python scripts/restore_clickhouse.py backups/clickhouse/<LATEST_BACKUP>.tar.gz --dangerously-overwrite-active-db
     ```

---

### Scenario C: Circuit Breaker Tripped (State: OPEN)
* **Symptoms:** Change requests rejected with `ExecutionBlockedException: Circuit breaker is OPEN`; UI banner displays Critical Circuit Breaker Warning.
* **Root Cause:** 3 consecutive rollout failures or post-check degradations within the failure threshold window.
* **Required Operator Actions:**
  1. Inspect recent `circuit_breaker_events` and `rollout_executions` in database or UI.
  2. Identify root cause: provider link packet loss, route map syntax mismatch, or BGP session instability.
  3. Verify router state manually via out-of-band console.
  4. Once network conditions are stabilized, manually reset the circuit breaker via UI (Super Admin) or SQL:
     ```sql
     INSERT INTO circuit_breaker_events (event_type, reason, actor_username) 
     VALUES ('MANUAL_RESET', 'Operator verified link stability after fiber cut resolution', 'admin');
     ```

---

### Scenario D: Rollout Rollback Failed (`NEEDS_MANUAL_REVIEW`)
* **Symptoms:** Rollout status changes to `FAILED` with `requires_manual_review=True`.
* **Root Cause:** Automated rollback command executed, but post-rollback verification detected persistent route divergence or speaker communication timeout.
* **Required Operator Actions:**
  1. **DO NOT** attempt automated re-execution.
  2. Access target edge router CLI directly.
  3. Review BGP routing table for the affected prefix:
     ```text
     show route <prefix> extensive
     ```
  4. Apply rollback configuration manually from change request `rollback_instructions`.
  5. Verify routing table convergence on downstream looking glass / BGP peers.
  6. In JDP UI, mark the change request as `REVERTED_MANUALLY` with detailed notes.

---

## 2. Recovery Verification Checklist
Before returning platform to normal operations:
- [ ] PostgreSQL container healthy and accepting connections.
- [ ] ClickHouse container healthy and responding to `/ping`.
- [ ] Go Flow Collector receiving and parsing UDP datagrams with 0 drop rate.
- [ ] SNMP polling background worker executing without timeouts.
- [ ] Active path probe worker updating RTT and loss within 30s freshness window.
- [ ] All safety flags confirmed locked to `false`:
  - `ROUTING_EXECUTION_ENABLED=false`
  - `PRODUCTION_ROUTING_ENABLED=false`
  - `FLOWSPEC_EXECUTION_ENABLED=false`
  - `RTBH_EXECUTION_ENABLED=false`
- [ ] Audit log entry recorded for the incident and recovery action.

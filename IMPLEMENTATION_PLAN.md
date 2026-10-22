# Implementation Plan: JDP Route Intelligence Platform

## 1. Executive Summary & Audit Hasil Workspace

- **Status Workspace Saat Ini:**
  - Workspace `noc flow` diaudit pada 22 Oktober 2026.
  - File yang ada sebelum implementasi:
    - `PRD_JDP_Route_Intelligence_Platform.pdf` (PRD resmi)
    - `PROMPT_ANTIGRAVITY_JDP_ROUTE_INTELLIGENCE.md` (Master Prompt)
  - Ruang kerja berada dalam status bersih (clean slate) tanpa kode peninggalan yang bertentangan. Seluruh file referensi dipertahankan secara utuh tanpa diubah atau dihapus.
- **Tujuan Sistem:**
  - Membangun **JDP Route Intelligence Platform**, aplikasi mandiri (self-hosted) untuk ISP/NOC yang setara dengan kelas fungsional Noction Flow Analyzer (NFA) dan Noction Intelligent Routing Platform (IRP), menggunakan arsitektur, algoritma, basis kode, dan desain UI orisinal.
  - Memisahkan secara ketat analitik aliran data berkecepatan tinggi (high-rate flow ingestion) dari logika bisnis dan kontrol perutean BGP.
  - Menegakkan prinsip keselamatan mutlak: seluruh instalasi awal berada dalam mode observasi/lab dengan `ROUTING_EXECUTION_ENABLED=false`.

---

## 2. Peta Tahapan (Phase Breakdown)

| Fase | Fokus | Deliverables Utama | Status |
|---|---|---|---|
| **Phase 0** | Fondasi Proyek, Arsitektur, & Lingkungan | Monorepo skeleton, Docker Compose, `.env.example`, `ARCHITECTURE.md`, ADR 0001-0004, skrip bootstrap | **Selesai** |
| **Phase 1** | Backend Core, Auth, RBAC, Metadata & Audit | FastAPI, SQLAlchemy models, Alembic migrations, JWT Auth, 5 Role RBAC, Audit Log append-only, Inventory CRUD | **Selesai** |
| **Phase 2** | High-Rate Flow Collector & Data Explorer | Go Flow Collector (NetFlow v5/v9, IPFIX, sFlow), parser fixtures, ClickHouse schema/storage, demo traffic simulator, Next.js Data Explorer | **Selesai** |
| **Phase 3** | SNMP & Interface Health Engine | SNMPv3 authPriv engine, AES secret encryption at rest, IF-MIB 64-bit HC math, reboot & counter wrap handling, Interface history DB, Scheduled Background Worker (concurrency limit, duplicate lock, stale detection, graceful shutdown), on-demand & scheduled device poll, dark NOC UI | **Selesai** |
| **Phase 4** | BGP Visibility & Active Path Probing | BGP session/route observer (RFC 7854 BMP TCP adapter with zero-crash parser, Initiation/Peer Up/Peer Down/Route Monitoring/Termination), BGPRoute table & RouteEvent stream, active ICMP/TCP connect probes with egress binding (SO_BINDTODEVICE on Linux vs Source IP on Windows), latency/jitter/loss historical analytics, worker telemetry, Next.js BGP Visibility NOC UI | **Selesai** |
| **Phase 5** | Routing Recommendation Engine & Simulator | Algoritma scoring deterministik multivariat (latency, loss, jitter, utilization, cost), anti-osilasi (hold-down, hysteresis, min improvement), candidate selection & allowlist filtering, dry-run route simulator & impact analysis, recommendation lifecycle, change request dual-approval workflow, frontend /optimization integration | **Selesai** |
| **Phase 6** | Isolated BGP Lab & Automated Rollback | Lab terisolasi GoBGP (AS 65001 & AS 65002), internal bridge network tanpa gateway eksternal, validasi injection & withdrawal, 11-point Pre-Check Engine, Post-Check convergence verifier, Automated Rollback Coordinator (kompensasi spesifik, deteksi parsial, retry terbatas, status NEEDS_MANUAL_REVIEW), Change Request lab testing evidence, API & Frontend Dashboard | **Selesai** |
| **Phase 7** | Production-Gated Optimization & DDoS Mitigation | 12-Point Backend Execution Gate, locked dry-run ProductionBGPAdapter, FlowSpec mitigation candidate workflow & multi-vendor syntax preview (Junos, Cisco, GoBGP), RTBH RFC 7999 host blackhole workflow with mandatory dual-approval & /24-/32 prefix bounds, Controlled Staged Rollout state machine (batch cap <= 5 prefixes), Circuit Breaker auto-trip & manual reset with root-cause justification, global Emergency Stop kill-switch, Frontend Optimization & Defense Dashboard | **Selesai** |
| **Phase 8** | Hardening, Backup/Restore Drill, & Operasional | Load testing flow collector, backup/restore scripts, disaster recovery guide, operational runbook | Rencana Fase 8 |

---

## 3. Arsitektur Komponen & Teknologi

1. **Frontend (`/frontend`):**
   - Next.js (App Router), TypeScript, Tailwind CSS, Lucide Icons, Recharts.
   - Tema gelap (Dark Mode NOC default) & terang, visualisasi data, label demo badge yang jujur, filter konsisten.
2. **Backend Application API (`/backend`):**
   - Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async), Alembic.
   - Pengesahan JWT, RBAC 5 tingkat: `super_admin`, `network_engineer`, `approver`, `noc_operator`, `auditor`.
   - Logging terstruktur (JSON format), penanganan error berseragam, audit trail append-only.
3. **High-Rate Flow Collector (`/collector`):**
   - Go 1.23 service mandiri dengan arsitektur worker-pool multithreaded.
   - Parsing NetFlow v5, NetFlow v9, IPFIX (RFC 7011), sFlow v5.
   - Normalisasi ke struktur seragam `FlowRecord`.
   - Metrik internal: total packets, flows parsed, parse errors, dropped datagrams, queue lag.
   - Pengiriman batch ke ClickHouse via native client/HTTP.
4. **Flow Analytics Storage (ClickHouse):**
   - Tabel `flow_records` berbasis `MergeTree` partitioned by month, ordered by `(site_id, exporter_ip, protocol, timestamp)`.
   - Tabel agregasi materialisasi `flow_hourly_agg` dan `flow_daily_agg`.
5. **Configuration & Metadata Database (PostgreSQL 16):**
   - Users, Roles, Sites, Providers, Devices, Interfaces, Collectors, Probe Targets, Scoring Policies, Change Requests, Approvals, Alerts, Audit Events.
6. **BGP Lab & Routing Engine:**
   - Isolated FRRouting/GoBGP container untuk pengujian route injection tanpa menyentuh jaringan produksi.

---

## 4. Aturan Keselamatan & Guardrail Routing

1. **Default Nonaktif:** Variabel `ROUTING_EXECUTION_ENABLED=false` pada `.env.example` dan server config.
2. **Allowlist Prefix & Peer Wajib:** Deny-by-default untuk seluruh prefix. Default route `0.0.0.0/0` dan `::/0`, martian, serta bogon otomatis ditolak.
3. **Change Control & Dual Approval:** Seluruh aksi perubahan rute harus melalui tahapan:
   `Draft` $\to$ `Simulated` $\to$ `Pending Approval` $\to$ `Approved` $\to$ `Lab Executed` $\to$ `Post-check Validated`.
4. **Circuit Breaker:** Membatasi maksimum rute delta dalam kurun waktu tertentu; penghentian darurat (kill-switch) mengembalikan rute ke baseline dalam waktu $< 5$ detik.
5. **No Secret Leaks:** Password, SNMP v3 auth/priv keys, BGP MD5 password, dan API tokens dilarang dicatat pada log maupun response API.

---

## 5. Rencana Pengujian (Testing Strategy)

- **Backend Tests:**
  - Unit tests: hashing password, pembuatan JWT token, RBAC permission checker, guardrail validator.
  - Integration tests: Auth flow (login, token refresh, logout, profile), Device CRUD, Interfaces, Collectors status, Audit logging.
  - **SNMP & Health Tests (Phase 3):**
    - 64-bit HC counter rate math (inbound/outbound bps, pps, utilization %).
    - Reboot detection (`sysUpTime` drop) & baseline reset tanpa spike palsu.
    - 64-bit counter wrapping ($2^{64}$ modulo) & supresi lonjakan anomali ($>10\times$ link speed).
    - Secret encryption at rest: AES-128-CBC dengan HMAC-SHA256 via Fernet (RFC 0x80) & pencegahan kebocoran kredensial di API/log/audit (lihat ADR 0008).
    - RBAC enforcement (network_engineer & super_admin only).
    - Unregistered / unauthorized IP scanning prevention (hanya perangkat inventaris aktif).
    - Status isolasi: kegagalan polling/timeout tidak mengubah `oper_status` antarmuka router.
    - Deteksi kegagalan otentikasi SNMPv3 (`auth_error`).
    - Pencegahan polling ganda serentak (in-flight concurrency lock per-device).
    - Stale device detection ($>180$ detik tidak ter-poll) & isolasi status.
    - Background worker single cycle execution, status telemetry endpoint, & graceful shutdown.
  - **BGP & Active Probing Tests (Phase 4):**
    - RFC 7854 BMP binary common header & per-peer header validation (V=0 IPv4, V=1 IPv6, 4-byte ASN, Router ID, timestamp).
    - Initiation message (Type 4) TLVs parsing (sysName, sysDescr).
    - Peer Up notification (Type 3) and Peer Down notification (Type 2) with reason codes.
    - Route Monitoring (Type 0) with encapsulated BGP UPDATE NLRI prefix announcements, withdrawals, AS_PATH, NEXT_HOP, and Communities parsing.
    - Message Type 1 (Stats Report) & Type 6 (Route Mirroring) ditegaskan di luar cakupan / unsupported via `BMPParseError` (lihat ADR 0009).
    - Zero-crash robustness: malformed, truncated, or out-of-sync binary BMP frames handled gracefully.
    - Ingestion pipeline into PostgreSQL: `BGPPeer`, `BGPRoute`, and `RouteEvent` stream synchronization.
    - BMP Adapter status telemetry endpoint (`/api/v1/bgp/bmp/status`) & simulation injector (`/api/v1/bgp/bmp/simulate`).
    - Active TCP connect 3-way handshake RTT latency measurement against open & closed ports (RST handling).
    - ICMP probe execution with unprivileged host ping fallback.
    - Multi-sample statistical aggregation: min, avg, max latency, jitter (MAD ms), and packet loss %.
    - Egress binding capability detection: `SO_BINDTODEVICE` on Linux vs `SOURCE_IP_BIND` on Windows, with explicit limitation documentation.
    - Target allowlist enforcement: arbitrary IP scanning strictly blocked (only registered targets allowed).
    - RBAC enforcement: `noc_operator` denied (403) from BMP simulation and probe target modification; `network_engineer` allowed.
  - **Recommendation Engine & Route Simulator Tests (Phase 5):**
    - Deterministic scoring math (scale 0.0 to 100.0, convention Higher Is Better, identical inputs produce identical scores).
    - Hard policy constraint enforcement (packet loss > 5% drops composite score to 0.0).
    - Missing data handling (neutral baseline 50.0, marked as 'missing', no silent zeroing, confidence penalized).
    - Data quality indicator & freshness evaluation (confidence % based on source presence and age penalties).
    - Insufficient data detection when essential telemetry is missing (recommends no optimization).
    - Anti-oscillation guardrails (minimum improvement threshold, hysteresis %, hold-down cooldown window).
    - Reproducibility & snapshot integrity (SHA-256 hash uniquely captures policy + telemetry inputs).
    - Prefix allowlist filtering in candidate selection (unallowlisted target prefixes rejected).
    - Default route simulation guardrail (requests for `0.0.0.0/0` and `::/0` strictly rejected with 400).
    - Route simulator dry-run execution (predicts latency, loss, and jitter delta, estimates flow volume shift from ClickHouse, declares assumptions and limitations, guarantees zero network changes).
    - Recommendation lifecycle transitions (`generated`, `under_review`, `approved`, `rejected`, `superseded`, `expired`, `cancelled`).
    - Recommendation deduplication (prevents redundant generation for same snapshot & candidate).
    - Change request creation from recommendation with PrefixAllowlist validation.
    - Anti-self-approval rule (requesters forbidden from approving their own change requests with 400).
    - Dual approval workflow (two distinct authorized accounts required for Step 1 partial approval and Step 2 final approval).
    - Policy re-validation at approval time (disallows approving if prefix allowlist was deactivated).
    - Expired and cancelled change request protection (approval attempts rejected).
    - Execution guardrail lock verification (`ROUTING_EXECUTION_ENABLED=false` blocks execution with 403 Forbidden).
    - Audit logging for evaluation, simulation, change request creation, dual-approvals, and rejections.
  - **Isolated BGP Lab & Automated Rollback Tests (Phase 6):**
    - Lab adapter prefix validation (allows lab prefixes, rejects default routes 0.0.0.0/0 & ::/0, bogons, unallowlisted prefixes).
    - Lab adapter peer IP validation against explicit lab allowlist (`10.99.0.10`, `10.99.0.20`).
    - 11-point safety Pre-Check Engine comprehensive pass under optimal lab conditions.
    - Pre-check safety lockout verification when `BGP_LAB_ENABLED=false`.
    - Pre-check strict rejection of default routes (`0.0.0.0/0`, `::/0`).
    - Pre-check strict rejection of unallowlisted prefixes (`10.250.0.0/24`).
    - Pre-check concurrency conflict prevention (blocks operations when in-progress run exists for same prefix).
    - Pre-check operation state compatibility (rejects withdrawal when prefix is absent; rejects announcement when prefix is already present).
    - Announce success lifecycle with post-check convergence verification on receiver (`bgp-speaker-2`).
    - Withdrawal success lifecycle with post-check absence verification on receiver.
    - Full roundtrip integration test (announce $\to$ verify convergence $\to$ withdraw $\to$ verify clean purged state).
    - Automated rollback coordinator on post-check failure (triggers compensatory withdrawal upon announcement failure, verifies state restored).
    - Rollback failure detection & manual review flagging (`NEEDS_MANUAL_REVIEW` status when compensating action fails repeatedly).
    - Manual review resolution workflow (`complete_manual_review` with engineer notes & audit log).
    - Change request integration (successful lab test records `lab_tested=True` and links `lab_test_run_id`).
    - API endpoints RBAC enforcement (`noc_operator` 403 Forbidden, `network_engineer` 201 Created).
    - Production routing execution guardrail permanent lockout (`ROUTING_EXECUTION_ENABLED=false` remains locked at 403 Forbidden).
    - Immutable audit event logging for all lab test runs (`BGP_LAB_ANNOUNCE_SUCCESS`, `BGP_LAB_WITHDRAW_SUCCESS`, etc.).
  - **Production-Gated Optimization & Mitigation Tests (Phase 7):**
    - Production execution flags locked by default (`ROUTING_EXECUTION_ENABLED=false`, `PRODUCTION_ROUTING_ENABLED=false`, `FLOWSPEC_EXECUTION_ENABLED=false`, `RTBH_EXECUTION_ENABLED=false`).
    - Production BGP Adapter locked in dry-run mode, 403 Forbidden on live execution attempts, syntax generation for Junos, Huawei, Cisco without network transmission.
    - 12-point backend Production Execution Gate evaluator: evaluates environment flags, router/peer allowlist, prefix policy, approval status, anti-self-approval, dual approval, lab test evidence, telemetry freshness, pre-check status, change window, audit readiness, and concurrency/circuit breaker.
    - Threat candidate lifecycle: formation, evidence snapshots, ClickHouse flow telemetry anomaly scanning, and status transitions.
    - FlowSpec mitigation workflow: typed rule schema validation, multi-vendor preview compilation (Junos, Cisco IOS-XR, GoBGP API JSON), default route rejection, anti-self-approval.
    - RTBH mitigation workflow: RFC 7999 blackhole community `65535:666`, host route length validation (/24-/32), rejection of broad subnets, mandatory distinct dual-approval.
    - Controlled staged rollout state machine: batch limits ($\le 5$ prefixes), canary stages (`DRAFT` $\to$ `POLICY_VALIDATED` $\to$ `LAB_TESTED` $\to$ `APPROVED` $\to$ `PRE_CHECK` $\to$ `CANARY` $\to$ `POST_CHECK` $\to$ `COMPLETED`), rollback handling.
    - Circuit Breaker failure threshold counter (3 strikes), auto-trip to `OPEN`, execution blocking, mandatory human reset with root-cause justification notes.
    - Global Emergency Stop kill-switch instantly halting all in-flight routing requests.
- **Collector Tests:**
  - Unit tests & fixtures: NetFlow v5 binary payload, NetFlow v9 template & data flowset, IPFIX binary payload, sFlow v5 sample packet (10/10 PASS).
  - Microbenchmarks: NetFlow v5 at 9.08M records/sec/core (3.3 microseconds/packet); NetFlow v9 at 2.78M records/sec/core (428 nanoseconds/record).
  - Error resilience: packet corrupt, truncated packet, unknown template handling without panics.
- **ClickHouse Storage & Ingestion:**
  - Ingestion throughput: 40,852 records/sec (average batch latency 107.7ms).
  - Query roundtrip test: Data Explorer (p50=48.2ms, p95=52.8ms), Top Talkers (p50=53.1ms, p95=59.3ms), Traffic Matrix (p50=50.4ms, p95=56.1ms).
- **Frontend Production Build:**
  - TypeScript compilation check (`tsc --noEmit`): 0 errors.
  - Production build (`next build`): 12/12 static routes optimized cleanly.
- **Phase 8 Hardening, Scalability & Disaster Recovery (Completed):**
  - PostgreSQL logical backup & restore drill verified on isolated target `jdp_route_intel_restore_test` (17/17 tables, 100% row match, SHA-256 verified).
  - ClickHouse backup & restore drill verified on isolated target `jdp_flow_analytics_restore_test` (5,000 records, 653 aggregates, sum(packets)/sum(bytes) identical, SHA-256 verified).
  - Retention maintenance script implemented with strict audit log immutability (`audit_events` never purged).
  - Operational runbooks published in `docs/runbooks/` (`disaster-recovery.md` and `operational-runbook.md`).
  - Full backend regression verification: 99 unique test cases passed out of 99 (100% success rate in 72.53s).
  - All execution flags remain locked to `false` for complete production network safety.


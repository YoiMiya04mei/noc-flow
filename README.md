# JDP Route Intelligence Platform

Platform mandiri (*self-hosted*) untuk tim Network Operations Center (NOC) dan Internet Service Provider (ISP), menggabungkan analisis aliran trafik skala besar sekelas Flow Analyzer (NetFlow v5/v9, IPFIX, sFlow) dan observasi serta rekomendasi optimasi perutean BGP cerdas sekelas IRP dengan basis kode, arsitektur, dan algoritma orisinal.

---

## 1. Arsitektur Komponen & Port

```
                        +---------------------------------------------+
                        |            Router / Switch / Firewall       |
                        +---------------------------------------------+
                               | NetFlow/IPFIX/sFlow (UDP)  | SNMP / BGP
                               v                            v
        +-----------------------------------------+   +-----------------------+
        | Go Flow Collector (:2055, :6343, :4739) |   | Poller & Active Probe |
        | - Non-blocking UDP Worker Pool          |   | - Latency/Loss/Jitter |
        | - Batched JSONEachRow Ingestion         |   +-----------------------+
        +-----------------------------------------+               |
                               |                                  |
                               v                                  v
        +-----------------------------------------+   +-----------------------+
        |     ClickHouse DB (:8123 / :9000)       |   | PostgreSQL 16 (:5432) |
        | - flow_records (MergeTree, Partitioned) |   | - Users, Roles, RBAC  |
        | - flow_hourly_agg (Materialized View)   |   | - Devices & Inventory |
        | - High-compression ZSTD Time-series     |   | - Audit Log (Append)  |
        +-----------------------------------------+   +-----------------------+
                               ^                                  ^
                               |                                  |
                               +----------------+-----------------+
                                                |
                                                v
                        +---------------------------------------------+
                        |        FastAPI Backend API (:8000)          |
                        | - REST API v1 (/api/v1)                     |
                        | - JWT Auth & 5-Level RBAC                   |
                        | - Recommendation Engine & Safety Guardrails |
                        +---------------------------------------------+
                                                ^
                                                | HTTP / JSON
                        +---------------------------------------------+
                        |         Next.js Web UI (:3000)              |
                        | - NOC Dark Mode Theme                       |
                        | - Data Explorer & Top Talkers               |
                        | - Safety Guardrail Status Banner            |
                        +---------------------------------------------+
```

### Port yang Digunakan
| Service | Protokol | Port | Deskripsi |
|---|---|---|---|
| **Go Flow Collector** | UDP | `2055` | Ingestion NetFlow v5 dan NetFlow v9 |
| **Go Flow Collector** | UDP | `6343` | Ingestion sFlow v5 |
| **Go Flow Collector** | UDP | `4739` | Ingestion IPFIX (RFC 7011) |
| **Go Flow Collector** | TCP | `8081` | Metrics internal & health check (`/metrics`, `/health`) |
| **ClickHouse** | TCP / HTTP | `8123` | ClickHouse HTTP interface |
| **ClickHouse** | Native | `9000` | ClickHouse native TCP client |
| **PostgreSQL** | TCP | `5432` | Database metadata aplikasi & audit |
| **FastAPI Backend** | TCP / HTTP | `8000` | REST API v1 (`/api/v1`), Swagger (`/api/v1/docs`) |
| **BMP TCP Adapter** | TCP | `11019` | RFC 7854 BGP Monitoring Protocol listener (Junos, FRRouting, Huawei) |
| **BGP Lab Speaker 1** | Internal TCP | `50051` | GoBGP Speaker 1 (AS 65001) gRPC API (terisolasi internal container) |
| **BGP Lab Speaker 2** | Internal TCP | `50052` | GoBGP Speaker 2 (AS 65002) gRPC API (terisolasi internal container) |
| **Next.js Web UI** | TCP / HTTP | `3000` | Dashboard web NOC |

---

## 2. Aturan Keselamatan & Guardrail Routing (Wajib)

1. **`ROUTING_EXECUTION_ENABLED=false` Secara Default**:
   - Seluruh instalasi awal berjalan pada mode observasi/lab. Modifikasi rute pada router jaringan produksi terkunci secara default pada level environment variable, database flag, dan dependensi API.
2. **`BGP_LAB_ENABLED=false` Secara Default**:
   - Fitur eksekusi lab hanya dapat berjalan jika diaktifkan secara eksplisit pada environment lab (`BGP_LAB_ENABLED=true`). Port BGP 179/TCP dilarang dipublikasikan ke host atau internet publik.
3. **Kebijakan Prefix Deny-by-Default**:
   - Prefix `0.0.0.0/0`, `::/0` (Default route), bogons (RFC 1918, RFC 6598, multicast), dan prefix yang tidak terdaftar pada `PrefixAllowlist` otomatis ditolak oleh validasi skema Pydantic.
4. **Workflow Dual Approval**:
   - Operator pemohon (*requester*) dilarang keras menyetujui (*approve*) perubahan rute miliknya sendiri. Perubahan rute berisiko tinggi wajib ditinjau oleh operator kedua dengan peran `approver` atau `super_admin`.
5. **Audit Trail Append-Only**:
   - Seluruh aksi login, penambahan allowlist, simulasi rute, approval, pengujian lab, rollback, dan perubahan perangkat dicatat secara permanen dan tidak dapat dihapus melalui antarmuka web.
6. **Perlindungan Rahasia (Zero Secret Leak)**:
   - Password, SNMP community string, dan BGP MD5 key tidak pernah ditampilkan dalam respons API atau dicatat dalam log terminal.

---

## 3. Cara Menjalankan Aplikasi Secara Lokal

### Opsi A: Menggunakan Docker Compose (Direkomendasikan untuk Produksi / Demo Lengkap)

1. Salin template environment:
   ```bash
   cp .env.example .env
   ```
2. Jalankan seluruh stack aplikasi standar:
   ```bash
   docker compose up -d --build
   ```
3. Menjalankan Isolated BGP Lab (GoBGP Dual Speakers):
   ```bash
   # Jalankan container lab GoBGP AS 65001 dan AS 65002
   docker compose --profile lab up -d
   ```
4. Menghentikan Isolated BGP Lab (tanpa menghapus database utama):
   ```bash
   docker compose --profile lab down
   ```
5. Pantau status container dan health check:
   ```bash
   docker compose ps
   ```
6. Jalankan migrasi dan seeding database pertama kali:
   ```bash
   docker compose exec backend python seed.py
   ```
5. Akses antarmuka:
   - **Web UI**: [http://localhost:3000](http://localhost:3000)
   - **Swagger OpenAPI Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
   - **Collector Health**: [http://localhost:8081/health](http://localhost:8081/health)

---

### Opsi B: Menjalankan Komponen Secara Lokal (Development)

#### 1. Backend (FastAPI)
```powershell
cd backend
$env:DATABASE_URL="sqlite+aiosqlite:///dev.db" # Atau PostgreSQL
python seed.py
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Flow Collector (Go)
```bash
cd collector
go run cmd/collector/main.go
```

#### 3. Frontend (Next.js)
```bash
cd frontend
npm run dev
```

---

## 4. Kredensial Pengguna Awal & Prosedur Bootstrap (RBAC)

Platform menggunakan otentikasi JWT dengan 5 tingkatan peran (*Role-Based Access Control* / RBAC):

| Peran (RBAC) | Hak Akses Utama |
|---|---|
| `super_admin` | Konfigurasi penuh, user management, audit trail, allowlist, policy manajemen |
| `network_engineer` | Analisis flow/BGP, registrasi device & probe, simulasi routing, draft mitigasi |
| `approver` | Review diff routing/mitigasi, approval / rejection change request (dual control) |
| `noc_operator` | Monitoring dashboard operasional, acknowledge incident, export report |
| `auditor` | Hak baca (*read-only*) untuk log audit dan laporan kepatuhan |

> [!IMPORTANT]
> **Kebijakan Keamanan Kredensial UAT & Produksi:**
> - Pada environment non-development (`APP_ENV=production` atau `APP_ENV=uat`), pembuatan akun demo default **dinonaktifkan secara otomatis**.
> - Administrator awal di-provisioning menggunakan script CLI interaktif atau variabel lingkungan:
>   ```bash
>   python scripts/bootstrap_admin.py --username admin --email admin@jdp-noc.net --role super_admin
>   ```
> - CLI di atas mendukung pembuatan interaktif (tanpa echo terminal), pengacakan password berkekuatan tinggi (`--generate`), serta verifikasi kekuatan password (minimal 12 karakter dengan huruf besar, kecil, angka, dan simbol).
> - Seluruh aktivitas provisioning dan rotasi password dicatat ke dalam `audit_events` tanpa pernah mencatat nilai password (zero secret leakage).

---

## 5. Ringkasan Pengujian yang Telah Dilakukan

### Pengujian Backend (FastAPI / Pytest)
```powershell
cd backend
python -m pytest tests/ -v
```
**Hasil: 99 dari 99 Test Lulus (100% Pass)**
- `test_login_success_form`: Validasi login form-data OAuth2.
- `test_login_success_json`: Validasi login JSON payload.
- `test_login_invalid_password`: Penolakan kredensial tidak valid.
- `test_get_current_user_me`: Pengecekan profil token aktif.
- `test_logout_creates_audit`: Verifikasi pencatatan audit saat logout.
- `test_guardrail_blocks_default_routes`: **Lolos** verifikasi penolakan `0.0.0.0/0` & `::/0`.
- `test_deny_by_default_blocks_unallowlisted_prefix`: **Lolos** penolakan prefix tanpa allowlist.
- `test_dual_approval_and_execution_guardrail`: **Lolos** pemblokiran eksekusi saat `ROUTING_EXECUTION_ENABLED=false`.
- `test_health_endpoints`: Pengujian `/health` dan `/ready`.
- `test_collector_registration_and_health`: Pengujian pendaftaran collector dan metrics health.
- `test_audit_trail_captures_events`: Pengujian integritas append-only audit log.
- `test_operator_cannot_create_device`: **Lolos** penolakan akses operator pada endpoint engineer (RBAC 403).
- `test_auditor_cannot_add_prefix_allowlist`: **Lolos** penolakan auditor memodifikasi policy (RBAC 403).
- `test_engineer_can_create_device`: Verifikasi izin engineer menambah router inventaris.
- `test_super_admin_can_add_prefix_allowlist`: Verifikasi izin superadmin mengelola allowlist.
- `test_auditor_can_read_audit_logs`: Verifikasi hak baca auditor pada rekaman audit.
- `test_counter_delta_regular_rate`: Kalkulasi tepat inbound/outbound bps dari counter 64-bit dan delta waktu.
- `test_counter_delta_pps_calculation`: Kalkulasi pps counter paket.
- `test_counter_delta_zero_change`: Strict 0 rate saat counter tidak berubah.
- `test_counter_delta_baseline_first_poll`: Penetapan baseline awal tanpa lonjakan tarif palsu.
- `test_device_reboot_detection_no_spike`: **Lolos** deteksi reboot router via `sysUpTime` drop, reset baseline tanpa spike.
- `test_counter_64bit_wrap_valid`: **Lolos** penanganan kalkulasi matematis modulo $2^{64}$ counter wrap.
- `test_counter_reset_anomaly_suppression`: **Lolos** supresi anomali jika candidate rate melebihi $10\times$ link capacity.
- `test_utilization_calculation`: Konversi kapasitas menjadi utilisasi % dan penanganan nilai `None` jika speed tidak tersedia.
- `test_snmp_secret_encryption_and_decryption`: Enkripsi secret at rest Fernet (AES-128) dan dekripsi terkontrol.
- `test_snmp_profile_create_and_secret_masking`: **Lolos** pencegahan mutlak kebocoran password pada respons API / audit log.
- `test_snmp_profile_rbac_restrictions`: **Lolos** penolakan role operator & auditor memodifikasi konfigurasi SNMP (403).
- `test_polling_unregistered_device_rejected`: **Lolos** penolakan scanning IP arbitrer (hanya perangkat terdaftar).
- `test_polling_rbac_operator_denied`: Pembatasan trigger poll khusus `network_engineer` dan `super_admin`.
- `test_full_device_polling_and_history_lifecycle`: Siklus penuh integrasi poll perangkat dan pencatatan histori database.
- `test_snmp_timeout_and_oper_status_preservation`: **Lolos** timeout handling tanpa mengubah status operasional interface menjadi down.
- `test_snmpv3_auth_failure_handling`: Deteksi kegagalan autentikasi SNMPv3 (`auth_error`).
- `test_duplicate_concurrent_poll_prevention`: **Lolos** pencegahan polling ganda serentak terhadap perangkat yang sama (in-flight concurrency lock).
- `test_stale_device_detection`: **Lolos** deteksi perangkat stale (>180 detik) dengan preservasi oper_status antarmuka.
- `test_snmp_worker_status_endpoint`: **Lolos** endpoint telemetri status worker background (`/api/v1/devices/snmp/worker-status`).
- `test_snmp_worker_single_cycle_and_shutdown`: **Lolos** eksekusi siklus background poller dan graceful shutdown lifecycle.
- `test_bmp_common_header_valid`: **Lolos** parsing header 6-byte RFC 7854 BMP v3.
- `test_bmp_malformed_header_handling`: **Lolos** penanganan paket biner terpotong / korup tanpa panic.
- `test_bmp_initiation_and_peer_up_message`: **Lolos** decoding BMP Initiation dan Peer Up info TLV.
- `test_bmp_peer_down_message`: **Lolos** decoding event BMP Peer Down dengan kode alasan RFC.
- `test_bmp_route_monitoring_update_and_withdraw`: **Lolos** decoding BGP UPDATE NLRI prefix announcements & withdrawals.
- `test_bmp_service_message_handling_and_normalization`: **Lolos** normalisasi event BMP ke tabel BGPPeer, BGPRoute, dan RouteEvent di DB.
- `test_egress_capabilities_detection`: **Lolos** deteksi kapabilitas platform (Linux SO_BINDTODEVICE vs Windows SOURCE_IP_BIND).
- `test_tcp_probe_connect_latency`: **Lolos** pengukuran round-trip latency SYN-ACK / RST pada port tujuan.
- `test_probe_stats_calculation`: **Lolos** perhitungan min, avg, max latency, jitter (MAD), dan packet loss %.
- `test_probe_target_crud_and_validation`: **Lolos** validasi CRUD target probe dan pembatasan IP target.
- `test_probe_target_rbac_restrictions`: **Lolos** pembatasan hak akses modifikasi target probe (khusus engineer & super_admin).
- `test_probe_immediate_execution_endpoint`: **Lolos** trigger eksekusi probe instan via API dengan RBAC.
- `test_probe_worker_status_and_stale_detection`: **Lolos** telemetri background probe worker dan penandaan target stale.
- `test_bgp_routes_api_endpoint`: **Lolos** query rute aktif BGP dengan filter prefix & peer.
- `test_bmp_status_and_simulator_endpoint`: **Lolos** monitoring adapter BMP dan endpoint injeksi fixture simulasi.
- `test_bmp_service_network_filtering`: **Lolos** pembatasan koneksi listener TCP BMP berdasarkan allowlist IP.
- `test_probe_unregistered_ip_rejected`: **Lolos** penolakan probe ke target yang tidak terdaftar.
- `test_bmp_zero_crash_on_corrupt_stream`: **Lolos** pemulihan stream TCP BMP saat menerima data acak (zero crash guarantee).
- `test_deterministic_scoring_math`: **Lolos** verifikasi formula deterministik skala 0-100 (Higher Is Better).
- `test_hard_policy_constraint_drops_score`: **Lolos** drop skor ke 0.0 jika packet loss > 5% melebihi batas kebijakan.
- `test_missing_data_neutral_handling`: **Lolos** missing metric diberi skor netral 50.0 (tanpa zeroing diam-diam) dan penalti confidence.
- `test_data_quality_and_freshness_evaluation`: **Lolos** evaluasi confidence % berbasis kelengkapan sumber data dan umur metrik.
- `test_insufficient_data_rejection`: **Lolos** deteksi insufficient data saat telemetri penting absen (rekomendasi tidak dipaksakan).
- `test_anti_oscillation_guardrails`: **Lolos** penegakan min improvement threshold, hysteresis %, dan cooldown hold-down window.
- `test_reproducibility_and_snapshot_hash`: **Lolos** verifikasi integritas snapshot hash SHA-256 untuk audit reproducibility 100%.
- `test_prefix_allowlist_filtering`: **Lolos** penolakan kandidat rute yang prefix-nya tidak terdaftar pada PrefixAllowlist.
- `test_route_simulator_blocks_default_routes`: **Lolos** penolakan simulasi rute default 0.0.0.0/0 dan ::/0 (400 Bad Request).
- `test_route_simulator_dry_run_execution`: **Lolos** eksekusi dry-run simulator rute (estimasi delta, estimasi volume flow ClickHouse, jaminan zero network mutation).
- `test_recommendation_lifecycle_transitions`: **Lolos** validasi transisi status rekomendasi (generated -> under_review -> approved -> superseded).
- `test_recommendation_deduplication`: **Lolos** pencegahan pembuatan rekomendasi duplikat untuk snapshot input dan rute yang sama.
- `test_change_request_from_recommendation`: **Lolos** pembentukan change request dari rekomendasi dengan validasi allowlist.
- `test_anti_self_approval_rule`: **Lolos** penolakan pemohon menyetujui change request miliknya sendiri (400 Bad Request).
- `test_dual_approval_workflow`: **Lolos** verifikasi alur dual approval (Step 1 partial approval oleh Approver A -> Step 2 final approval oleh Approver B).
- `test_change_request_allowlist_revalidation`: **Lolos** penolakan approval jika prefix allowlist dinonaktifkan sebelum approval diproses.
- `test_expired_and_cancelled_change_requests`: **Lolos** penolakan approval terhadap change request yang telah kedaluwarsa atau dibatalkan.
- `test_execution_guardrail_always_locked`: **Lolos** jaminan guardrail eksekusi jaringan terkunci secara permanen (HTTP 403 Forbidden).
- `test_audit_logging_across_lifecycle`: **Lolos** pencatatan audit log append-only untuk setiap evaluasi rekomendasi, simulasi, dan approval.
- `test_lab_adapter_prefix_and_peer_validation`: **Lolos** validasi prefix lab dan IP peer lab AS 65001 & AS 65002.
- `test_lab_precheck_11_points_pass`: **Lolos** evaluasi komprehensif 11-point Pre-Check Engine.
- `test_lab_roundtrip_test_lifecycle`: **Lolos** siklus announce -> verify receiver -> withdraw -> verify clean state.
- `test_lab_automated_rollback_on_postcheck_failure`: **Lolos** trigger rollback otomatis kompensasi withdraw saat konvergensi gagal.
- `test_production_execution_flags_locked_by_default`: **Lolos** penguncian default seluruh flag eksekusi produksi (`false`).
- `test_production_adapter_dry_run_and_execution_lock`: **Lolos** kompilasi sintaks dry-run Junos/Huawei/Cisco dan blokir 403 saat live.
- `test_12_point_execution_gate_evaluator`: **Lolos** evaluasi 12 kriteria keamanan deny-by-default sebelum eksekusi rute.
- `test_threat_candidate_lifecycle`: **Lolos** pembentukan kandidat ancaman DDoS, deteksi anomali, dan transisi status.
- `test_flowspec_preview_and_rule_lifecycle`: **Lolos** preview multi-vendor Junos/Cisco/GoBGP, penolakan default route, dan anti-self-approval.
- `test_rtbh_mitigation_dual_approval_and_prefix_guards`: **Lolos** validasi prefix /24-/32 blackhole RFC 7999, penolakan subnet luas (< /24), default routes, allowlist check, dan mandatory dual-approval 2-tahap.
- `test_controlled_rollout_lifecycle_and_batch_limits`: **Lolos** pembatasan batch <= 5 prefix dan transisi canary staging.
- `test_circuit_breaker_and_emergency_stop`: **Lolos** auto-trip pada 3 kegagalan, emergency stop kill-switch instan, dan manual reset dengan telaah akar masalah.

### Pengujian High-Rate Flow Collector (Go Test Suite)
```bash
docker run --rm -v "${PWD}/collector:/app" -w /app golang:1.23-alpine go test -v ./...
```
**Hasil: 10 dari 10 Test Lulus (100% Pass)**
- `TestParseValidNetFlow5`: Parsing biner NetFlow v5 dengan sampling rate adjustment.
- `TestParseTruncatedPacketDoesNotPanic`: Uji ketahanan crash terhadap paket rusak/terpotong.
- `TestParseInvalidVersion`: Deteksi versi header selain v5.
- `TestParseNetFlow9Valid`: Pembacaan Template FlowSet dan Data FlowSet terpisah.
- `TestParseNetFlow9CorruptedDoesNotPanic`: Ketahanan parser v9 terhadap byte corrupt.
- `TestIPFIXShortPacketError`: Penanganan paket IPFIX pendek tanpa panic.
- `TestIPFIXInvalidVersion`: Validasi versi 10 pada RFC 7011 IPFIX.
- `TestSFlow5ShortPacketError`: Penanganan sFlow pendek.
- `TestSFlow5InvalidVersion`: Validasi header version 5 sFlow.
- `TestDecodeEthernetPacket`: Ekstraksi paket Ethernet, IPv4, dan L4 UDP/TCP dari sFlow sample.

### Pengujian Frontend (Next.js & TypeScript)
```powershell
cd frontend
npx tsc --noEmit
npm run build
```
**Hasil: 12 Halaman Statis Terkompilasi Bersih (0 Type Errors)**
- `/` (Overview NOC)
- `/traffic` (Traffic Intelligence & Data Explorer)
- `/devices` (Device & SNMP Interface Monitoring with Scheduled Polling Worker Telemetry & Recharts History)
- `/collectors` (Collector Health)
- `/bgp` (BGP Visibility & Active Path Probing with BMP Adapter Telemetry, Route Explorer, & Egress Diagnostics)
- `/optimization` (Route Optimization & Simulator)
- `/alerts` (Alerts & Incidents)
- `/audit` (Audit Trail)
- `/admin` (Administration & Policies)

---

## 6. Status Fitur: Berfungsi Nyata vs Data Demo

| Modul | Status Implementasi | Status Data |
|---|---|---|
| **Autentikasi & JWT** | **Berfungsi Penuh** | Nyata (Argon2id/bcrypt hashed, bearer token) |
| **RBAC (5 Peran)** | **Berfungsi Penuh** | Nyata (Ditegakkan di backend FastAPI pada tiap route) |
| **Database Migrations** | **Berfungsi Penuh** | Nyata (Alembic versi `0001`, `0002_snmp_engine`, `0003_bgp_bmp_and_probing`, `0004_recommendation_and_approval_workflow`, `0005_bgp_lab_and_rollback`, & `0006_phase7_mitigation_and_rollout`) |
| **Audit Trail** | **Berfungsi Penuh** | Nyata (Append-only PostgreSQL table) |
| **SNMP Polling Engine** | **Berfungsi Penuh** | Nyata (SNMPv3 authPriv AES/SHA + IF-MIB 64-bit) |
| **Scheduled Background Poller** | **Berfungsi Penuh** | Nyata (Asyncio worker dalam lifespan, semaphore limit, in-flight duplicate lock) |
| **Worker Telemetry & Trigger** | **Berfungsi Penuh** | Nyata (`/api/v1/devices/snmp/worker-status` & `/worker-trigger`) |
| **Secret Encryption at Rest** | **Berfungsi Penuh** | Nyata (AES-128-CBC dengan HMAC-SHA256 via Fernet RFC 0x80, zero secret leakage; lihat ADR 0008) |
| **Interface Rate & Wrap Math** | **Berfungsi Penuh** | Nyata (Delta time, reboot reset, 64-bit wrap, no fake spikes) |
| **Interface Metrics History** | **Berfungsi Penuh** | Nyata (Tersimpan di PostgreSQL `interface_metrics_history`) |
| **Flow Collector (Go)** | **Berfungsi Penuh** | Nyata (UDP listeners NetFlow v5/v9, IPFIX, sFlow v5) |
| **Parser Fixtures & Tests**| **Berfungsi Penuh** | Nyata (Uji biner otomatis, zero crash) |
| **Demo Traffic Simulator** | **Berfungsi Penuh** | Sintetis berlabel `is_demo=1` (Pipa transmisi nyata) |
| **ClickHouse Ingestion** | **Berfungsi Penuh** | Nyata (Schema MergeTree partitioned by month + views) |
| **Data Explorer** | **Berfungsi Penuh** | Nyata jika ClickHouse terhubung; fallback demo berlabel jujur |
| **BGP Visibility & Peers** | **Berfungsi Penuh** | Nyata dengan adapter BMP RFC 7854 dan pelabelan sumber LIVE/LAB/SIMULATED |
| **BMP Adapter (RFC 7854)** | **Berfungsi Penuh** | Nyata (Asyncio TCP Listener port 11019, Message Type 0 Route Monitoring, Type 2 Peer Down, Type 3 Peer Up, Type 4 Initiation, Type 5 Termination; Type 1 Stats & Type 6 Mirroring di luar cakupan; lihat ADR 0009) |
| **Active Path Probing** | **Berfungsi Penuh** | Nyata (TCP connect RTT / ICMP, min/avg/max/loss/jitter, background worker 15s) |
| **Egress Binding Engine** | **Berfungsi Penuh** | Nyata (Platform capability detection: SO_BINDTODEVICE Linux vs SOURCE_IP_BIND Windows) |
| **Recommendation Engine** | **Berfungsi Penuh** | Nyata (Korelasi BGP RIB, Active Probes, SNMP link capacity, ClickHouse flows, scoring policy) |
| **Deterministic Scoring Math** | **Berfungsi Penuh** | Nyata (Skala 0-100, Higher Is Better, normalisasi multivariat, hard constraints, missing data policy, SHA-256 snapshot) |
| **Anti-Oscillation Engine** | **Berfungsi Penuh** | Nyata (Min improvement delta 10.0, hysteresis 15%, hold-down cooldown 15m) |
| **Route Simulator (Dry-Run)** | **Berfungsi Penuh** | Nyata (What-if analysis, deltas, traffic shift estimate, zero network mutation) |
| **Change Request & Dual Approval** | **Berfungsi Penuh** | Nyata (2-step dual approver, anti-self-approval, allowlist revalidation, rollback plan metadata) |
| **Route Execution Guardrail**| **Berfungsi Penuh** | Nyata (Terkunci ke `false`, blokir 403 Forbidden) |
| **Isolated BGP Lab (GoBGP)** | **Berfungsi Penuh** | Nyata (Topologi dual speaker AS 65001 & AS 65002, internal Docker network, port 179 tidak dipublikasikan ke publik) |
| **11-Point Pre-Check Engine**| **Berfungsi Penuh** | Nyata (Pemeriksaan kesehatan, session Established, allowlist prefix & peer, martian/bogon check, default route reject, status compatibility, concurrency lock, audit) |
| **Post-Check Convergence Verifier** | **Berfungsi Penuh** | Nyata (Verifikasi konvergensi rute aktual pada receiver via gRPC/JSON, AS-PATH, Next-Hop, verifikasi penghapusan rute saat withdraw) |
| **Automated Rollback Coordinator** | **Berfungsi Penuh** | Nyata (Aksi kompensasi terarah withdraw/announce, idempotensi, timeout & retry terbatas, deteksi kegagalan & penandaan `NEEDS_MANUAL_REVIEW`) |
| **Change Request Lab Integration** | **Berfungsi Penuh** | Nyata (Hasil uji lab dicatat sebagai bukti verifikasi `lab_tested=True`, dual approval tetap utuh, produksi tetap terkunci) |
| **12-Point Backend Execution Gate** | **Berfungsi Penuh** | Nyata (Evaluator 12 kriteria keamanan produksi deny-by-default, blokir 403 jika salah satu kriteria tidak terpenuhi) |
| **Production BGP Adapter (Dry-Run)**| **Berfungsi Penuh** | Nyata (Kompilasi sintaks multi-vendor Junos, Huawei, Cisco; transmisi fisik terkunci 403 Forbidden) |
| **FlowSpec Mitigation Workflow** | **Berfungsi Penuh** | Nyata (Deteksi anomali flow, preview sintaks multi-vendor Junos/Cisco/GoBGP, validasi skema typed, anti-self-approval) |
| **RTBH Mitigation Workflow** | **Berfungsi Penuh** | Nyata (RFC 7999 community `65535:666`, validasi host /24-/32, penolakan subnet luas, mandatory dual-approval 2-langkah) |
| **Controlled Staged Rollout** | **Berfungsi Penuh** | Nyata (State machine DRAFT->POLICY_VALIDATED->LAB_TESTED->APPROVED->PRE_CHECK->CANARY->COMPLETED, batas batch <= 5 prefix) |
| **Circuit Breaker & Emergency Stop** | **Berfungsi Penuh** | Nyata (Auto-trip pada 3 kegagalan, kill-switch instan, manual reset wajib disertai telaah akar masalah oleh operator) |

---

## 7. Panduan Konfigurasi SNMPv3 authPriv pada Router Lab

Berikut konfigurasi perangkat lab yang direkomendasikan agar siap dipolling oleh JDP Route Intelligence Platform:

### 1. Juniper Junos (MX / QFX / SRX)
```text
set snmp v3 usm local-engine user jdp-snmp-user authentication-sha authentication-password "SuperAuthSecret123"
set snmp v3 usm local-engine user jdp-snmp-user privacy-aes128 privacy-password "SuperPrivSecret456"
set snmp v3 vacm security-to-group security-model usm security-name jdp-snmp-user group jdp-noc-group
set snmp v3 vacm access group jdp-noc-group default-context-prefix model usm level privacy read-view jdp-if-mib
set snmp v3 view jdp-if-mib oid .1.3.6.1.2.1.1 include
set snmp v3 view jdp-if-mib oid .1.3.6.1.2.1.2 include
set snmp v3 view jdp-if-mib oid .1.3.6.1.2.1.31 include
commit
```

### 2. Huawei VRP (NE40E / ATN / CloudEngine)
```text
system-view
snmp-agent
snmp-agent sys-info version v3
snmp-agent group v3 jdp-noc-group privacy read-view jdp-if-view
snmp-agent mib-view included jdp-if-view iso
snmp-agent usm-user v3 jdp-snmp-user group jdp-noc-group
snmp-agent usm-user v3 jdp-snmp-user authentication-mode sha
(masukkan auth password: SuperAuthSecret123)
snmp-agent usm-user v3 jdp-snmp-user privacy-mode aes128
(masukkan priv password: SuperPrivSecret456)
commit
return
```

### 3. MikroTik RouterOS (v7)
```text
/snmp
set enabled=yes
/snmp community add name=jdp-sec-community security=private
/snmp user
add name=jdp-snmp-user auth=sha auth-password="SuperAuthSecret123" \
    enc=aes priv-password="SuperPrivSecret456" group=read
```

---

## 8. Phase 8 Completion: Hardening, Scalability & Production Readiness

Phase 8 has been completed with comprehensive hardening, disaster recovery drills, performance benchmarking, and operational runbooks:

1. **Backup & Isolated Restore Drills:**
   - PostgreSQL logical backup & restore verified into isolated test DB (`jdp_route_intel_restore_test`) with 100% row matching across 17 tables and SHA-256 verification.
   - ClickHouse DDL & data restore verified into isolated test DB (`jdp_flow_analytics_restore_test`) with 100% aggregation matching.
   - Automated drill execution script: `python scripts/run_backup_restore_drill.py`.

2. **Data Retention & Maintenance:**
   - Script: `python scripts/retention_maintenance.py [--execute]`.
   - Raw flow records: 30-day cutoff; Hourly aggregates: 90-day cutoff.
   - SNMP interface history: 90 days; Active probes & route events: 30 days.
   - **Audit Log Immutability:** `audit_events` compliance log is strictly exempt from purge.

3. **Performance Benchmarks:**
   - Go Parser NetFlow v5: 9.08M records/sec/core (3.3 microseconds/packet).
   - Go Parser NetFlow v9: 2.78M records/sec/core (428 nanoseconds/record).
   - ClickHouse Ingestion: 40,852 records/sec (average batch latency: 107.7ms).
   - Query Latency (Data Explorer, Top Talkers, Traffic Matrix): p50 < 54ms, p95 < 60ms.

4. **Operational Runbooks:**
   - [Disaster Recovery Runbook](file:///c:/Users/permadi%20pratama/OneDrive/文档/Project%20antigravity/noc%20flow/docs/runbooks/disaster-recovery.md)
   - [Operational Runbook](file:///c:/Users/permadi%20pratama/OneDrive/文档/Project%20antigravity/noc%20flow/docs/runbooks/operational-runbook.md)
   - [ADR 0007: Phase 8 Architecture](file:///c:/Users/permadi%20pratama/OneDrive/文档/Project%20antigravity/noc%20flow/docs/adr/0007-hardening-scalability-and-production-readiness.md)

5. **Safety Guardrails Status:**
   - `ROUTING_EXECUTION_ENABLED=false` (Production router configuration push blocked)
   - `PRODUCTION_ROUTING_ENABLED=false`
   - `FLOWSPEC_EXECUTION_ENABLED=false`
   - `RTBH_EXECUTION_ENABLED=false`




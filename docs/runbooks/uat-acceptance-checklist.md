# JDP Route Intelligence Platform — Controlled Acceptance Test (UAT) Package

## Dokumen Referensi & Pedoman Pelaksanaan UAT
- **Versi Dokumen**: 1.0.0-RC1
- **Target Branch**: `uat-readiness-hardening`
- **Tingkat Akses**: Terbatas — Tim NOC, Network Engineering, dan Tim Audit Kepatuhan
- **Status Eksekusi Produksi**: **TERKUNCI PENUH (READ-ONLY / LAB MODE)**
- **Prasyarat Global**:
  1. Seluruh flags eksekusi produksi bernilai `false`:
     - `ROUTING_EXECUTION_ENABLED=false`
     - `PRODUCTION_ROUTING_ENABLED=false`
     - `FLOWSPEC_EXECUTION_ENABLED=false`
     - `RTBH_EXECUTION_ENABLED=false`
  2. BGP Lab terisolasi pada bridge Docker internal (`jdp-bgp-speaker-1`, `jdp-bgp-speaker-2`).
  3. Kredensial super administrator telah di-bootstrap menggunakan `python scripts/bootstrap_admin.py` (tanpa menggunakan password demo).
  4. Tidak ada kredensial yang dicatat dalam log, output terminal, atau repositori Git.

> [!IMPORTANT]
> **Instruksi Pengisian Operator UAT:**
> - Kolom **Actual Result**, **Status (PASS/FAIL/BLOCKED)**, **Bukti Log / Output**, dan **Catatan Operator** diisi secara bertahap sesuai batch pengujian yang disetujui.
> - Operator penguji WAJIB mengisi kolom tersebut secara langsung saat pengujian dilaksanakan di lingkungan acceptance lab yang terisolasi.
> - Jangan menandai PASS sebelum output verifikasi atau log aktual terkonfirmasi.

### Ringkasan Status Eksekusi per Batch

| Batch | Domain / Test ID | Deskripsi Skenario | Status Eksekusi |
|---|---|---|---|
| **Batch 1** | **UAT-SAFE-01** | Production Execution Guardrails & Secret Masking | **PASS** |
| **Batch 1** | **UAT-INST-01** | Isolated Fresh Installation & Cold Start Persistence | **PASS** |
| **Batch 2** | **UAT-AUTH-01** | Autentikasi, Token Expiration, & 5 Peran RBAC | *(Belum Dieksekusi)* |
| **Batch 2** | **UAT-SNMP-01** | Inventory, SNMPv3 Polling, & Stale State | *(Belum Dieksekusi)* |
| **Batch 2** | **UAT-FLOW-01** | Flow Collector Ingestion, ClickHouse, & Data Explorer | *(Belum Dieksekusi)* |
| **Batch 3** | **UAT-BMP-01** | BMP RFC 7854 Visibility & Active Path Probes | *(Belum Dieksekusi)* |
| **Batch 3** | **UAT-REC-01** | Recommendation Scoring & Simulation Reproducibility | *(Belum Dieksekusi)* |
| **Batch 3** | **UAT-CR-01** | Change Request, Dual Approval, & Anti-Self Approval | *(Belum Dieksekusi)* |
| **Batch 4** | **UAT-LAB-01** | Isolated BGP Lab, Convergence Check, & Rollback | *(Belum Dieksekusi)* |
| **Batch 4** | **UAT-MITIG-01** | FlowSpec & RTBH Multi-Vendor Preview & 12-Pt Gate | *(Belum Dieksekusi)* |
| **Batch 4** | **UAT-BCK-01** | Backup & Isolated Restore Drill | *(Belum Dieksekusi)* |
| **Batch 4** | **UAT-RESIL-01**| Fault-Isolation & Auto-Recovery Service Dependency | *(Belum Dieksekusi)* |

---

## Matriks UAT Skenario Pengujian

### 1. Fresh Installation & Cold Start

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-INST-01** |
| **Prasyarat** | Docker Compose project terisolasi `jdp-uat-isolated` (`docker-compose.uat.yml`) dengan database dan volume terpisah: `jdp-uat-postgres` (port 5435), `jdp-uat-clickhouse` (port 8125, 9002), volume terpisah `jdp-uat-isolated_jdp_uat_postgres_vol`, `jdp-uat-isolated_jdp_uat_clickhouse_vol`. Database target `jdp_uat_route_intel` bersih (empty cold-start). Port dev existing (5433, 8123) dan volume dev tetap aktif tanpa gangguan. |
| **Langkah Pengujian** | 1. Inisialisasi stack terisolasi: `docker compose -p jdp-uat-isolated -f docker-compose.uat.yml up -d postgres clickhouse`.<br>2. Verifikasi status kontainer via `docker ps` hingga status `Up (healthy)`.<br>3. Jalankan migrasi skema database dari kondisi kosong: `alembic upgrade head` mengarah ke database UAT terisolasi.<br>4. Inisialisasi akun super administrator UAT: `python scripts/bootstrap_admin.py --username uat_admin --generate`.<br>5. Eksekusi pengujian verifikasi otomatis UAT (`scripts/test_uat_install.py`):<br>   - Verifikasi `/health`.<br>   - Uji login OAuth2 form (`/api/v1/auth/login`) dan JSON (`/api/v1/auth/login-json`).<br>   - Uji verifikasi profile super_admin (`/api/v1/auth/me`).<br>   - Uji inventaris kosong awal (`/api/v1/devices`).<br>   - Uji status production adapter (`LOCKED_DRY_RUN`) & circuit breaker (`CLOSED`).<br>   - Uji penolakan eksekusi routing fisik (HTTP 403 `ERR_ROUTING_EXECUTION_DISABLED`).<br>6. Uji persistensi data: Restart kontainer database `docker restart jdp-uat-postgres`, lalu jalankan ulang seluruh harness verifikasi. |
| **Expected Result** | Seluruh kontainer terisolasi berjalan sehat (`Up healthy`). Migrasi Alembic membuat seluruh 27 tabel dari cold-start tanpa error. Akun administrator UAT terbuat dan mencatat audit event tanpa membocorkan password. Login berhasil dan mengembalikan token JWT. Status guardrail terkunci rapat. Setelah restart kontainer database, seluruh data dan skema tetap utuh (persisten). Lingkungan development existing tidak terpengaruh sama sekali. |
| **Actual Result** | **LULUS (VERIFIED)**.<br>- Kontainer `jdp-uat-postgres` (port 5435) dan `jdp-uat-clickhouse` (port 8125/9002) berjalan sehat.<br>- Migrasi Alembic `001_initial_schema` sukses membentuk 27 tabel relasional lengkap di `jdp_uat_route_intel`.<br>- Akun `uat_admin` (role `super_admin`) berhasil di-bootstrap dengan audit event `USER_BOOTSTRAP_CREATED` tercatat di database.<br>- Endpoint `/health` mengembalikan status 200 OK `{"status": "healthy", "routing_execution_enabled": false}`.<br>- Login OAuth2 form & JSON mengembalikan token JWT bearer valid.<br>- Query `/auth/me` memvalidasi username `uat_admin` dan role `super_admin`.<br>- Status production adapter mengonfirmasi `safety_mode: LOCKED_DRY_RUN` dan `is_enabled: false`.<br>- Percobaan eksekusi routing ditolak dengan HTTP 403 `ERR_ROUTING_EXECUTION_DISABLED`.<br>- Database persistence terverifikasi: pasca `docker restart jdp-uat-postgres`, seluruh 27 tabel dan kredensial admin tetap utuh, seluruh assertion pengujian lulus 100%. |
| **PASS / FAIL / BLOCKED** | **PASS** |
| **Bukti Log atau Output** | - `docker ps`: `jdp-uat-postgres Up (healthy) 0.0.0.0:5435->5432/tcp`, `jdp-uat-clickhouse Up (healthy) 0.0.0.0:8125->8123/tcp`<br>- Alembic output: `[ALEMBIC TARGET DB]: postgresql+asyncpg://...:5435/jdp_uat_route_intel`, `Running upgrade -> 001_initial_schema, Initial schema for JDP Route Intelligence Platform`<br>- Bootstrap output: `Admin user 'uat_admin' created successfully (role: super_admin). Audit event ID: 1`<br>- Verification harness: `[1] Health Check: Status 200`, `[2] Login uat_admin (Form): Status 200 (JWT acquired)`, `[2b] Login uat_admin (JSON): Status 200`, `[3] /auth/me Profile: Status 200 | User: uat_admin, Role: super_admin`, `[4] /devices Query: Status 200 | Count: 0`, `[5] /mitigation/production-adapter/status: Status 200 | is_enabled: False, safety_mode: LOCKED_DRY_RUN`, `[5b] Circuit Breaker: Status 200 | State: CLOSED`, `[6] Route Execution Test: Status 403 | Detail: ERR_ROUTING_EXECUTION_DISABLED`<br>- Restart persistence: `docker restart jdp-uat-postgres` -> `ALL UAT-INST-01 INTEGRATION CHECKS PASSED SUCCESSFULLY!` |
| **Catatan Operator** | Pengujian fresh installation dilakukan pada environment yang 100% terisolasi (port 5435 & 8125, volume `jdp-uat-isolated_*`). Database development (`jdp-postgres` port 5433) dan volume `nocflow_postgres_data` sama sekali tidak tersentuh dan tetap berjalan normal. Kredensial password UAT di-generate acak dengan entropi tinggi dan tidak dicatat dalam laporan maupun repositori. |

---

### 2. Autentikasi, Token Expiration, dan 5 Peran RBAC

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-AUTH-01** |
| **Prasyarat** | Backend aktif pada port 8000, 5 peran RBAC telah dibuat (`super_admin`, `network_engineer`, `approver`, `noc_operator`, `auditor`). |
| **Langkah Pengujian** | 1. POST `/api/v1/auth/login` menggunakan kredensial tidak valid.<br>2. POST `/api/v1/auth/login` menggunakan kredensial `super_admin` yang valid.<br>3. Verifikasi respons JWT token (`access_token`, `token_type: bearer`, `expires_in`).<br>4. Uji token expiration dengan mengirim token kedaluwarsa ke `/api/v1/auth/me`.<br>5. POST `/api/v1/auth/logout` dan periksa pencatatan audit log.<br>6. Uji hak akses endpoint inventaris (`POST /api/v1/devices`):<br>   - Uji dengan token `noc_operator` (harus 403 Forbidden).<br>   - Uji dengan token `network_engineer` (harus 201 Created).<br>7. Uji hak akses audit log (`GET /api/v1/audit/logs`):<br>   - Uji dengan token `noc_operator` (harus 403 Forbidden).<br>   - Uji dengan token `auditor` (harus 200 OK). |
| **Expected Result** | - Login salah ditolak HTTP 401 Unauthorized.<br>- Login valid menghasilkan JWT bearer token.<br>- Token kedaluwarsa ditolak HTTP 401 `Token has expired`.<br>- Logout berhasil dan mencatat event `LOGOUT` di `audit_events`.<br>- RBAC ditegakkan ketat: `noc_operator` mendapat 403 Forbidden saat create device, `network_engineer` diizinkan; `auditor` dapat membaca audit log tetapi tidak dapat mengubah policy. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan response JSON HTTP & query audit_events)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 3. Inventory, SNMPv3 Polling, Stale State, & Histori Interface

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-SNMP-01** |
| **Prasyarat** | Database PostgreSQL aktif, perangkat router lab/mock tersedia, profil SNMPv3 authPriv AES/SHA terdaftar. |
| **Langkah Pengujian** | 1. Registrasikan SNMP Profile dengan priv_protocol `AES` dan auth_protocol `SHA` via `POST /api/v1/devices/snmp/profiles`.<br>2. Periksa respons API dan tabel database untuk memastikan password terenkripsi via Fernet (AES-128-CBC + HMAC-SHA256) dan tidak bocor sebagai plaintext.<br>3. Daftarkan router Cisco/Juniper di `/api/v1/devices`.<br>4. Trigger polling SNMP manual via `POST /api/v1/devices/{id}/snmp/poll`.<br>5. Verifikasi perhitungan bps/pps counter 64-bit pada antarmuka.<br>6. Matikan interface/router sementara untuk memicu timeout SNMP.<br>7. Verifikasi bahwa status operasional antarmuka (`oper_status`) TIDAK langsung diubah menjadi down hanya karena 1x polling timeout.<br>8. Biarkan router tidak merespons $>180$ detik dan verifikasi flag `is_stale=true` pada `/api/v1/devices/snmp/worker-status`.<br>9. Query endpoint histori antarmuka `/api/v1/devices/{id}/interfaces/{if_id}/history` dan verifikasi retensi data. |
| **Expected Result** | - Password SNMP tersimpan terenkripsi di PostgreSQL (format `gAAAAA...`), respons API mengembalikan masked value `***`.<br>- Polling membaca OID IF-MIB dan menghitung rate delta bps/pps secara akurat.<br>- Polling timeout tidak merusak status operasional perangkat.<br>- Deteksi perangkat stale berfungsi setelah 180 detik tanpa data baru.<br>- Histori metrik antarmuka tersimpan runut di `interface_metrics_history`. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan log polling, JSON masked profile, dan output history)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 4. Flow Collector Ingestion, ClickHouse Ingestion, Data Explorer, & Top Talkers

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-FLOW-01** |
| **Prasyarat** | Go Flow Collector running pada port UDP 2055, 6343, 4739; ClickHouse running pada port 8123. |
| **Langkah Pengujian** | 1. Kirim stream NetFlow v5 sintetis menggunakan generator trafik UDP ke port 2055.<br>2. Kirim stream NetFlow v9 template-based ke port 2055.<br>3. Kirim stream IPFIX (RFC 7011) ke port 4739 dan sFlow v5 ke port 6343.<br>4. Periksa metrik internal collector: `GET http://localhost:8081/metrics`.<br>5. Verifikasi batch buffer flushing ke ClickHouse tabel `jdp_flow_analytics.flow_records`.<br>6. Buka halaman frontend Data Explorer (`/explorer`) dan jalankan query filter berdasarkan Exporter IP, Rentang Waktu, dan Port Aplikasi.<br>7. Verifikasi widget **Top Talkers** (Top Source IP, Top Destination IP, Top ASNs, Protocol Breakdown).<br>8. Verifikasi bahwa data sintetis menampilkan badge `[DEMO DATA]` atau `[SIMULATED]` secara transparan jika simulator aktif. |
| **Expected Result** | - Collector memproses seluruh datagram tanpa packet drop (`packets_received` meningkat, `parse_errors=0`).<br>- ClickHouse menerima batch records (tercatat di `flow_records` dengan partisi bulan).<br>- Query analitik Data Explorer merespons dalam waktu $<100\text{ ms}$.<br>- Top talkers teragregasi akurat berdasarkan volume byte dan paket.<br>- Badge transparansi sumber data tampil jelas pada dashboard frontend. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan screenshot UI Top Talkers & query SELECT count() FROM flow_records)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 5. BMP RFC 7854 Visibility, Route Event Stream, & Active Path Probes

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-BMP-01** |
| **Prasyarat** | BMP Adapter listening pada TCP 11019, router peer atau BGP route reflector terkonfigurasi untuk mengirim BMP feed. |
| **Langkah Pengujian** | 1. Hubungkan sesi BMP dari router/speaker lab ke TCP port 11019.<br>2. Verifikasi penerimaan dan decoding **Initiation Message (Type 4)** (`sysName`, `sysDescr`).<br>3. Verifikasi penerimaan **Peer Up Notification (Type 3)** dan pembaruan tabel `bgp_peers` menjadi `Established`.<br>4. Kirim BGP UPDATE rute baru via **Route Monitoring (Type 0)** dan verifikasi penambahan ke tabel `bgp_routes`.<br>5. Simulasikan penarikan rute (withdrawn routes) dan verifikasi event `ROUTE_WITHDRAWN` di `route_events`.<br>6. Kirim frame BMP yang tidak didukung: **Statistics Report (Type 1)** atau **Route Mirroring (Type 6)**.<br>7. Verifikasi bahwa parser menolak Type 1 & 6 dengan `BMPParseError` secara aman tanpa menyebabkan crash atau memutus koneksi worker.<br>8. Jalankan active path probe: daftarkan target probe via `POST /api/v1/probes/targets` (ICMP & TCP connect RTT).<br>9. Verifikasi eksekusi probe setiap interval 15 detik dan verifikasi kalkulasi latency, jitter (MAD), serta packet loss di `probe_results`. |
| **Expected Result** | - BMP Initiation, Peer Up, Peer Down, dan Route Monitoring ter-decode 100% akurat.<br>- Event rute tercatat realtime pada tabel `route_events`.<br>- Message Type 1 dan Type 6 ditolak secara terkontrol tanpa crash (memenuhi jaminan *zero-crash resilience*).<br>- Active path probe menghitung RTT ms dan jitter secara akurat sesuai egress binding platform. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan output log BMP listener, isi tabel route_events, dan hasil probe_results)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 6. Recommendation Engine Scoring & Simulation Reproducibility

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-REC-01** |
| **Prasyarat** | Data telemetri flow, BGP routes, active probe RTT, dan SNMP interface capacity tersedia; Scoring Policy aktif terdaftar. |
| **Langkah Pengujian** | 1. Konfigurasi Scoring Policy (`latency_weight=0.35`, `loss_weight=0.30`, `jitter_weight=0.15`, `utilization_weight=0.10`, `cost_weight=0.10`).<br>2. Trigger evaluasi rekomendasi via `POST /api/v1/recommendations/evaluate`.<br>3. Periksa nilai skor komposit (skala 0.0 – 100.0, konvensi *Higher Is Better*).<br>4. Verifikasi bahwa jika packet loss $>5\%$, hard constraint langsung menjatuhkan skor komposit menjadi 0.0.<br>5. Verifikasi penanganan missing telemetry: metrik yang tidak tersedia diberi nilai baseline 50.0 (tidak di-nolkan diam-diam) dan nilai confidence % diturunkan secara proporsional.<br>6. Verifikasi anti-oscillation: candidate route dengan peningkatan skor $<10.0$ poin atau dalam periode hold-down (15 menit) ditekan/ditolak.<br>7. Periksa nilai `input_snapshot_hash` (SHA-256) pada rekomendasi yang dihasilkan.<br>8. Jalankan Route Simulator `POST /api/v1/recommendations/simulate` dengan snapshot hash yang sama dan verifikasi bahwa skor dan output simulasi identik 100% (*deterministic reproducibility*).<br>9. Uji simulasi terhadap prefix default `0.0.0.0/0` atau `::/0` (harus ditolak HTTP 400 Bad Request). |
| **Expected Result** | - Skor dihitung deterministik dengan pembobotan matematis yang benar.<br>- Hard constraint loss $>5\%$ menggugurkan kandidat rute.<br>- Missing data diperlakukan transparan tanpa halusinasi data.<br>- Anti-oscillation mencegah flapping rute bolak-balik.<br>- Snapshot hash SHA-256 menjamin auditabilitas dan audit reproducibility.<br>- Default route dilarang keras disimulasikan. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan payload JSON breakdown skor, snapshot hash, dan bukti penolakan 0.0.0.0/0)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 7. Change Request, Dual Approval, Anti-Self Approval, & Policy Rejection

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-CR-01** |
| **Prasyarat** | Pengguna dengan peran `network_engineer` dan `approver` tersedia; tabel `prefix_allowlists` terisi. |
| **Langkah Pengujian** | 1. Login sebagai `network_engineer` (User A).<br>2. Buat Change Request untuk prefix yang TIDAK terdaftar di prefix allowlist (harus ditolak HTTP 400 / 422).<br>3. Buat Change Request valid untuk prefix yang terdaftar di allowlist (`103.145.2.0/24`).<br>4. Verifikasi status awal Change Request: `pending_approval`.<br>5. Sebagai User A (`network_engineer`), coba lakukan approval terhadap Change Request milik sendiri via `POST /api/v1/change-requests/{id}/approve`.<br>6. Verifikasi bahwa sistem menolak dengan HTTP 400 `Self-approval is strictly forbidden under dual-approval separation of duties`.<br>7. Login sebagai `approver` (User B) yang berbeda.<br>8. Lakukan rejection pada Change Request uji coba dengan alasan `"Cost variance exceeds monthly budget"`. Verifikasi status berubah menjadi `rejected` dan dicatat di audit log.<br>9. Buat Change Request baru, login sebagai User B (`approver`), lalu lakukan approval.<br>10. Verifikasi status berubah menjadi `approved` dan instruksi rollback tersimpan lengkap. |
| **Expected Result** | - Prefix di luar allowlist ditolak sejak tahap drafting.<br>- Self-approval diblokir mutlak oleh sistem (pemisahan tugas dual control ditegakkan).<br>- Approver independen dapat menyetujui atau menolak Change Request disertai alasan yang tercatat di audit trail.<br>- Metadata rollback tersimpan lengkap dan tidak dapat diubah setelah approval. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan response JSON penolakan self-approval dan log approval User B)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 8. Isolated BGP Lab Announce, Withdrawal, Convergence Post-Check, & Automated Rollback

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-LAB-01** |
| **Prasyarat** | Kontainer `jdp-bgp-speaker-1` (AS 65001) dan `jdp-bgp-speaker-2` (AS 65002) berjalan pada Docker bridge internal; `BGP_LAB_ENABLED=true` di environment lab. |
| **Langkah Pengujian** | 1. Verifikasi konektivitas gRPC ke speaker lab port 50051 dan 50052.<br>2. Jalankan **11-Point Pre-Check**: verifikasi pengecekan status session BGP, allowlist prefix lab (`10.100.1.0/24`), peer IP, lock konkurensi, dan pencegahan bogon/default route.<br>3. Eksekusi pengumuman rute lab: `POST /api/v1/bgp/lab/announce` dengan prefix `10.100.1.0/24`.<br>4. Verifikasi **Post-Check Convergence**: sistem melakukan kueri ke speaker penerima (`jdp-bgp-speaker-2`) dan memvalidasi bahwa rute benar-benar diterima di RIB penerima dengan Next-Hop yang sesuai.<br>5. Simulasikan kegagalan post-check (misalnya dengan menyetel expected community yang sengaja salah).<br>6. Verifikasi **Automated Rollback**: sistem secara otomatis memicu withdrawal rute kompensasi, mengembalikan status speaker ke kondisi semula, dan mencatat event rollback.<br>7. Jika rollback gagal disimulasikan, verifikasi bahwa status ditandai secara eksplisit sebagai `NEEDS_MANUAL_REVIEW` dan memicu notifikasi peringatan kritis.<br>8. Lakukan penarikan rute lab yang sukses via `POST /api/v1/bgp/lab/withdraw` dan verifikasi rute terhapus dari RIB penerima. |
| **Expected Result** | - 11-Point Pre-Check memvalidasi seluruh parameter keamanan sebelum injeksi.<br>- Rute terinjeksi ke speaker lab dan konvergensi diverifikasi pada speaker penerima.<br>- Kegagalan konvergensi langsung memicu automated rollback tanpa intervensi manual.<br>- Penarikan rute terverifikasi bersih pada tabel routing penerima.<br>- Tidak ada paket atau rute yang bocor ke luar lingkungan container lab. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan log gRPC BGP speaker, hasil konvergensi RIB, dan audit event rollback)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 9. FlowSpec & RTBH Preview, 12-Point Execution Gate, Emergency Stop, & Circuit Breaker

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-MITIG-01** |
| **Prasyarat** | Modul Phase 7 terpasang, flags `FLOWSPEC_EXECUTION_ENABLED=false` dan `RTBH_EXECUTION_ENABLED=false`. |
| **Langkah Pengujian** | 1. Generate candidate threat DDoS via `POST /api/v1/mitigation/threats/evaluate`.<br>2. Buat draft aturan FlowSpec via `POST /api/v1/mitigation/flowspec/rules` (misal drop UDP port 53 traffic $>50\text{ Mbps}$).<br>3. Verifikasi fitur **Multi-Vendor Syntax Preview**: periksa kompilasi sintaks untuk Junos (`firewall family inet filter...`), Cisco (`class-map...`), dan GoBGP API payload.<br>4. Buat draft mitigasi RTBH via `POST /api/v1/mitigation/rtbh/rules` untuk host /32 yang diserang. Verifikasi penolakan terhadap subnet luas ($</24$).<br>5. Lakukan approval mitigasi dengan dual-approval approver independen.<br>6. Coba eksekusi mitigasi ke perangkat produksi via `POST /api/v1/mitigation/flowspec/{id}/execute`.<br>7. Verifikasi bahwa **12-Point Execution Gate** memblokir eksekusi dengan HTTP 403 Forbidden karena flag `FLOWSPEC_EXECUTION_ENABLED=false`.<br>8. Uji **Emergency Stop**: panggil endpoint darurat `POST /api/v1/mitigation/emergency-stop`.<br>9. Verifikasi bahwa status beralih ke `EMERGENCY_STOP_ACTIVE` dan seluruh aktivitas routing terkunci total.<br>10. Uji **Circuit Breaker**: simulasikan 3 kegagalan eksekusi beruntun dan verifikasi bahwa sirkuit berpindah ke status `OPEN` (memblokir seluruh eksekusi baru hingga manual reset dilakukan oleh operator setelah akar masalah teratasi). |
| **Expected Result** | - Preview sintaks FlowSpec multi-vendor dikompilasi akurat sesuai spesifikasi RFC 5575.<br>- RTBH memvalidasi community `65535:666` dan menolak subnet luas.<br>- 12-Point Backend Gate memblokir eksekusi fisik 100% saat flag false.<br>- Emergency Stop dan Circuit Breaker mengunci sistem secara instan dan memerlukan reset manual berotoritas tinggi. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan kompilasi syntax FlowSpec preview, log blokir 403, dan status Circuit Breaker)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 10. Backup & Isolated Restore Drill (PostgreSQL & ClickHouse)

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-BCK-01** |
| **Prasyarat** | Script `scripts/backup_postgres.py`, `scripts/restore_postgres.py`, `scripts/backup_clickhouse.py`, `scripts/restore_clickhouse.py` tersedia; direktori `backups/` siap. |
| **Langkah Pengujian** | 1. Jalankan backup otomatis PostgreSQL: `python scripts/backup_postgres.py`.<br>2. Verifikasi file terkompresi `.sql.gz`, checksum `.sha256`, dan metadata `.manifest.json`.<br>3. Jalankan backup ClickHouse: `python scripts/backup_clickhouse.py`.<br>4. Verifikasi arsip skema dan partisi data `.tar.gz` dan `.sha256`.<br>5. Jalankan restore drill terisolasi: `python scripts/run_backup_restore_drill.py`.<br>6. Verifikasi bahwa script restore secara tegas menolak memulihkan langsung ke database produksi aktif (`jdp_route_intel` atau `jdp_flow_analytics`).<br>7. Verifikasi bahwa database pengujian terisolasi (`jdp_route_intel_restore_test` dan `jdp_flow_analytics_restore_test`) dibuat secara terpisah.<br>8. Verifikasi keutuhan skema, tabel, indeks, dan kesesuaian jumlah baris (*row count validation*) antara database sumber dan database hasil restore.<br>9. Verifikasi pembersihan database test setelah drill selesai. |
| **Expected Result** | - File backup terbuat lengkap dengan checksum SHA-256 yang valid.<br>- Restore drill berhasil 100% memulihkan data ke database isolasi tanpa mengganggu database operasional.<br>- Jumlah baris dan skema tabel terverifikasi identik.<br>- Guardrail proteksi database utama berfungsi mencegah penimpaan database operasional. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan log terminal run_backup_restore_drill.py dan verifikasi checksum)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 11. Resiliency & Graceful Recovery Ketika Service Dependency Berhenti

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-RESIL-01** |
| **Prasyarat** | Seluruh stack service berjalan normal (`docker compose ps`). |
| **Langkah Pengujian** | 1. Hentikan ClickHouse sementara: `docker compose stop clickhouse`.<br>2. Akses backend FastAPI (`GET /api/v1/health`) dan dashboard frontend (`/devices`, `/optimization`).<br>3. Verifikasi bahwa backend tidak mengalami unhandled crash/panic; fitur yang hanya membutuhkan PostgreSQL tetap beroperasi normal, sedangkan Data Explorer menampilkan penanganan fallback yang elegan (*graceful degradation*).<br>4. Nyalakan kembali ClickHouse: `docker compose start clickhouse`.<br>5. Verifikasi koneksi ClickHouse pulih secara otomatis tanpa restart backend.<br>6. Hentikan PostgreSQL sementara: `docker compose stop postgres`.<br>7. Verifikasi bahwa backend mengembalikan pesan error terstruktur HTTP 503 Service Unavailable (tanpa membocorkan connection string, password, atau internal trace).<br>8. Nyalakan kembali PostgreSQL dan verifikasi auto-reconnect pool database backend. |
| **Expected Result** | - Sistem mengimplementasikan *fault-isolation*: kegagalan ClickHouse tidak mematikan modul routing, SNMP, atau autentikasi.<br>- Tidak ada unhandled panic atau memory leak.<br>- Re-koneksi otomatis (*auto-recovery*) berjalan mulus saat service dependensi kembali online.<br>- Tidak ada kredensial atau stack trace internal yang bocor pada respon error HTTP. |
| **Actual Result** | *(Diisi oleh Operator saat UAT)* |
| **PASS / FAIL / BLOCKED** | *(Belum Dieksekusi)* |
| **Bukti Log atau Output** | *(Lampirkan log backend saat stop/start dependensi dan HTTP response status)* |
| **Catatan Operator** | *(Catatan operator)* |

---

### 12. Pemeriksaan Menyeluruh: Seluruh Production Execution Flags Tetap Nonaktif

| Kolom | Rincian Skenario |
|---|---|
| **Test ID** | **UAT-SAFE-01** |
| **Prasyarat** | Akses ke environment konfigurasi backend `.env.uat` / `.env`, modul `app/core/config.py`, database `system_settings`, unit & integration test suite, dan API endpoints. |
| **Langkah Pengujian** | 1. Audit konfigurasi environment aktual:<br>   - Periksa nilai `ROUTING_EXECUTION_ENABLED` (harus `false`).<br>   - Periksa nilai `PRODUCTION_ROUTING_ENABLED` (harus `false`).<br>   - Periksa nilai `FLOWSPEC_EXECUTION_ENABLED` (harus `false`).<br>   - Periksa nilai `RTBH_EXECUTION_ENABLED` (harus `false`).<br>   - Periksa nilai `BGP_LAB_ENABLED` (harus `false` pada konfigurasi umum).<br>2. Eksekusi test suite guardrails dan mitigasi produksi:<br>   - `pytest tests/test_guardrails.py tests/test_mitigation_and_rollout.py -v`<br>   - `pytest tests/test_bgp_lab.py -k "test_lab_precheck_fails_when_lab_disabled or test_lab_production_guardrail_unaffected or test_lab_audit_logging" -v`<br>   - `pytest tests/test_snmp.py -k "test_snmp_profile_create_and_secret_masking" -v`<br>3. Panggil endpoint live dengan token `super_admin`: `POST /api/v1/change-requests/1/execute`.<br>4. Periksa status production adapter via `GET /api/v1/mitigation/production-adapter/status` dan circuit breaker via `GET /api/v1/mitigation/circuit-breaker/status`.<br>5. Verifikasi bahwa adapter produksi beroperasi dalam status `LOCKED_DRY_RUN` tanpa socket fisik ke router produksi.<br>6. Verifikasi enkripsi kredensial (Fernet AES-128-CBC + HMAC-SHA256) dan penyamaran kredensial `***` pada API response dan log audit. |
| **Expected Result** | - Seluruh flag eksekusi bernilai `false` secara definitif.<br>- Seluruh percobaan eksekusi diblokir secara absolut pada layer guardrail backend (HTTP 403 `ERR_ROUTING_EXECUTION_DISABLED`).<br>- Tidak ada perubahan konfigurasi atau rute yang terkirim ke perangkat jaringan produksi.<br>- Upaya eksekusi tercatat rapi di tabel `audit_events`.<br>- Kredensial tidak pernah bocor dalam respons JSON maupun log sistem.<br>- Seluruh unit test guardrail lulus 100%. |
| **Actual Result** | **LULUS (VERIFIED)**.<br>- Konfigurasi default terverifikasi aman:<br>  * `ROUTING_EXECUTION_ENABLED = false`<br>  * `PRODUCTION_ROUTING_ENABLED = false`<br>  * `FLOWSPEC_EXECUTION_ENABLED = false`<br>  * `RTBH_EXECUTION_ENABLED = false`<br>  * `BGP_LAB_ENABLED = false`<br>- 15 test guardrails dan isolasi lulus 100% (11/11 pada test guardrails/mitigation, 3/3 pada test BGP lab guardrail, 1/1 pada secret masking).<br>- Pemanggilan endpoint live `POST /api/v1/change-requests/1/execute` ditolak mutlak dengan HTTP 403 Forbidden: `ERR_ROUTING_EXECUTION_DISABLED: Physical routing execution is strictly disabled by system guardrails`.<br>- Status production adapter terverifikasi: `safety_mode: LOCKED_DRY_RUN`, `is_enabled: false`.<br>- Status circuit breaker: `state: CLOSED`.<br>- Secret protection terverifikasi: SNMPv3 auth & priv keys terenkripsi di database dan dimasking menjadi `***` saat di-query via API. Tidak ada kebocoran secret pada respon API maupun log. |
| **PASS / FAIL / BLOCKED** | **PASS** |
| **Bukti Log atau Output** | - Pytest output: 15 passed across `test_guardrails.py`, `test_mitigation_and_rollout.py`, `test_bgp_lab.py`, and `test_snmp.py`.<br>- HTTP 403 Response: `status=403, detail="ERR_ROUTING_EXECUTION_DISABLED: Physical routing execution is strictly disabled by system guardrails"`<br>- Adapter Status: `GET /api/v1/mitigation/production-adapter/status` -> `{"is_enabled": false, "safety_mode": "LOCKED_DRY_RUN", "total_executions_attempted": 0, "total_executions_blocked": 0}`<br>- Circuit Breaker Status: `GET /api/v1/mitigation/circuit-breaker/status` -> `{"state": "CLOSED", "failure_count": 0}`<br>- Masking check: `tests/test_snmp.py::test_snmp_profile_create_and_secret_masking PASSED` |
| **Catatan Operator** | Seluruh guardrail eksekusi produksi (10-layer backend protection, 12-point execution gate, production adapter dry-run lock, circuit breaker, dan emergency stop) terbukti aktif, read-only, dan menolak interaksi fisik tanpa ada jalur bypass melalui API atau UI. Zero production mutations. |

---

## Lembar Pengesahan Kesiapan UAT

| Peran | Nama Personel | Tanda Tangan / Status | Tanggal Verifikasi |
|---|---|---|---|
| **Lead Network Engineer** | _______________________ | [ ] SIAP UAT / [ ] DITOLAK | ____ / ____ / 2026 |
| **NOC Operations Lead** | _______________________ | [ ] SIAP UAT / [ ] DITOLAK | ____ / ____ / 2026 |
| **Security & Compliance Auditor** | _______________________ | [ ] SIAP UAT / [ ] DITOLAK | ____ / ____ / 2026 |
| **Platform Architect** | _______________________ | [ ] SIAP UAT / [ ] DITOLAK | ____ / ____ / 2026 |

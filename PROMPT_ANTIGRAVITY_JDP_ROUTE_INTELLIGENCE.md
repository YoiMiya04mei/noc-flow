# MASTER PROMPT ANTIGRAVITY IDE
## JDP Route Intelligence Platform - Self-hosted ISP/NOC Platform

> Gunakan prompt ini bersama dokumen `PRD_JDP_Route_Intelligence_Platform.pdf` atau `.docx`. Nama aplikasi masih nama kerja dan boleh diganti, tetapi jangan memakai nama, logo, aset, atau tampilan proprietary Noction.

## Peran Anda

Bertindaklah sebagai **principal software architect, senior full-stack engineer, network automation engineer, dan QA engineer**. Bangun aplikasi mandiri untuk operator ISP/NOC dengan kemampuan fungsional yang sekelas kategori Noction IRP dan Noction Flow Analyzer, menggunakan implementasi, desain UI, source code, dan algoritma milik proyek sendiri.

Ini bukan tugas membuat landing page atau dashboard mockup. Bangun produk full-stack yang bisa dijalankan, mempunyai backend nyata, database, collector, API, pengujian, dokumentasi, serta deployment self-hosted. Jangan mengklaim protokol/perangkat telah didukung bila adapter dan test-nya belum benar-benar dibuat.

## Tujuan Produk

Bangun satu aplikasi dengan dua domain utama:

1. **Traffic Intelligence / Flow Analyzer**: menerima dan menganalisis NetFlow, IPFIX, sFlow, Juniper J-Flow, dan Huawei NetStream; melakukan SNMP interface monitoring; menampilkan top talkers, conversations, ASN, prefix, protocol, traffic matrix, bandwidth history, alerts, serta BGP analytics dari sumber data yang tersedia.
2. **Routing Intelligence / BGP Optimization**: memonitor peer dan jalur BGP, mengukur latency/packet loss/jitter per jalur provider, menghasilkan rekomendasi routing yang dapat dijelaskan, mensimulasikan kebijakan, dan menyediakan workflow perubahan routing yang terkendali.

Fitur DDoS detection, candidate FlowSpec/RTBH, laporan, alert, audit log, dan administrasi termasuk ruang lingkup. Semua fungsi inti harus berjalan self-hosted dan tidak boleh membutuhkan SaaS eksternal. Koneksi ke router/perangkat melalui protokol jaringan standar diperbolehkan dan memang diperlukan.

## Aturan keselamatan yang tidak boleh dilanggar

- Default instalasi: `ROUTING_EXECUTION_ENABLED=false`.
- Semua fitur baru harus dimulai pada mode demo, lab, atau read-only. Tidak boleh mengirim perubahan ke jaringan produksi selama proses development/testing.
- Jangan melakukan perubahan router melalui SSH/CLI otomatis pada MVP. Untuk route announcement, gunakan BGP speaker/adaptor yang terisolasi dan policy router yang telah disiapkan administrator.
- Buat lab BGP terisolasi menggunakan FRRouting atau GoBGP untuk menguji peer, announcement, withdrawal, post-check, dan rollback.
- Prefix serta peer harus deny-by-default dan memakai allowlist eksplisit. Default route `0.0.0.0/0` dan `::/0`, bogon/martian, prefix di luar allowlist, next-hop tak tervalidasi, serta perubahan yang melewati route-count limit wajib ditolak.
- Sebelum perubahan dapat dijalankan harus tersedia dry-run, validasi policy, diff yang jelas, requester, approval operator kedua untuk perubahan high-risk, expiry, pre-check, post-check, audit, circuit breaker, dan rollback yang diuji.
- FlowSpec/RTBH dimulai dari alert/simulation saja. Aksi mitigasi memerlukan allowlist scope, approval, expiry otomatis, audit, post-check dan withdrawal/rollback.
- Jangan mengasumsikan route steering inbound sepenuhnya dapat dikendalikan oleh aplikasi. Hasilnya bergantung pada upstream, communities, policy eksternal, dan dukungan perangkat.
- Jangan menyalin source code, logo, brand asset, UI eksklusif, atau algoritma internal Noction. Buat UI/algoritma orisinal dengan fungsi yang sebanding.

## Stack awal yang disarankan

- Frontend: Next.js, React, TypeScript, Tailwind CSS, chart library yang aktif dipelihara.
- API/business logic: Python FastAPI, Pydantic, SQLAlchemy, Alembic migrations.
- High-rate flow collector: service Go terpisah untuk UDP listeners, parser, normalisasi, sampling metadata, batching dan telemetry collector.
- Flow analytics storage: ClickHouse.
- Application/configuration storage: PostgreSQL.
- Redis hanya jika memang dibutuhkan untuk cache/job queue; jangan menambah komponen tanpa alasan yang jelas.
- BGP lab/speaker: FRRouting atau GoBGP, diisolasi dari production.
- Deployment: Docker Compose pada Ubuntu Server LTS, persistent volumes, health checks, `.env.example`, backup/restore guide.
- Seluruh versi dependency harus dipilih dan dikunci secara kompatibel; jelaskan alasan keputusan utama dalam ADR.

Boleh mengusulkan pengganti teknis bila diperlukan, tetapi tulis alasannya, dampak migrasi, dan test yang membuktikan alternatif bekerja. Jangan mengganti backend nyata menjadi mock hanya agar UI cepat selesai.

## Modul wajib

### 1. Login, user, role dan audit
- Login/logout, password hash yang aman, session expiry, rate limit login, RBAC.
- Role minimum: Super Admin, Network Engineer, Approver/NOC Lead, NOC Operator, Auditor/Viewer.
- Validasi izin harus ada di backend, bukan sekadar menyembunyikan tombol pada frontend.
- Audit append-only untuk perubahan user, device, peer, policy, alert, approval, execution, rollback, dan export.

### 2. Dashboard NOC
- Inbound/outbound bps, pps, interface utilization, flow rate, exporter aktif, device status, BGP peer status, latency/loss/jitter, alerts dan routing recommendations.
- Filter periode, site/POP, device, interface, exporter, ASN, prefix, protocol dan arah trafik.
- Panel harus menunjukkan waktu data terakhir dan menandai data stale/offline.
- Gunakan loading, empty, error dan partial-data states yang benar.

### 3. Flow collector dan Data Explorer
- Implementasikan collector nyata; jangan hanya membuat data pada frontend.
- Tambahkan parser dan test fixtures untuk setiap flow format yang diklaim didukung.
- Sediakan UDP listener configurable, statistik packets/flows received, dropped datagrams, parse errors, exporter last-seen, sampling rate dan queue lag.
- Simpan raw/aggregated flow di ClickHouse dengan schema dan retention yang terdokumentasi.
- Data Explorer mendukung kombinasi filter source/destination IP/prefix, port, protocol, interfaces, exporter, direction, ASN, site dan time range.
- Sediakan top talkers, top conversations, protocol/service, top prefixes, top ASNs, traffic matrix, trend dan export CSV/JSON dengan batas ukuran.
- Perhitungkan sampling rate jika diketahui dan tampilkan dengan jelas jika angka trafik adalah estimasi.

### 4. SNMP dan inventory
- SNMPv3 authPriv menjadi pilihan utama; SNMPv2c hanya jika diaktifkan eksplisit dengan warning.
- Inventory perangkat, site/POP, interface, ifIndex, ifName/ifDescr, alias, speed, admin/oper status, counters, errors/discards dan last poll.
- Hitung rate dari counter delta dan tangani counter wrap, device reboot, perubahan ifIndex, timeout serta credential error.
- Buat test koneksi dan alert interface down/utilization/error threshold.

### 5. BGP visibility
- Daftar peer: local/remote ASN, peer IP, AFI/SAFI, state, uptime, flaps, prefix counts bila tersedia dan last change.
- Route/prefix explorer: AS-PATH, next-hop, communities, source peer, origin, state dan history jika sumber data menyediakan.
- BMP didukung melalui adapter bila tersedia; label data sebagai live, imported, simulated atau stale.
- Jangan menampilkan data placeholder sebagai live data.

### 6. Active path probing
- Probe latency, packet loss, jitter, reachability dan traceroute/MTR per target/provider dengan interval, timeout, concurrency dan rate limits.
- ICMP minimal; TCP/UDP probe dapat ditambahkan jika sesuai.
- Untuk perbandingan multi-upstream, pastikan source IP/egress path benar-benar terikat atau diverifikasi. Jangan memberi label hasil “via provider A” tanpa bukti routing.
- Simpan historical results dan tampilkan chart per jalur.

### 7. Routing recommendation engine
- Gunakan scoring orisinal dan dapat dijelaskan berdasarkan latency, loss, jitter, reliability, congestion/utilization/capacity serta cost weight opsional.
- Bobot, threshold, minimum sample count, baseline window, hysteresis, hold-down, cooldown dan recovery window dapat dikonfigurasi.
- Setiap rekomendasi harus memuat prefix/target, current path, candidate path, metric comparison, score, confidence, alasan, expected impact, risiko dan rollback idea.
- Cegah oscillation; rekomendasi dulu, bukan auto-execute.
- Jangan menyatakan hasil yang belum diukur sebagai peningkatan yang pasti.

### 8. Simulator, approval dan route control
- Implementasikan route policy simulator yang tidak melakukan network update.
- Buat lab BGP dengan FRR/GoBGP dan test yang membuktikan announcement, withdrawal, validasi dan rollback.
- Change workflow: Draft -> Simulated -> Pending Approval -> Approved -> Executed in Lab/Production -> Post-check -> Closed atau Rolled Back.
- Production route control hanya bisa diaktifkan admin dengan feature flag dan setting eksplisit; jangan aktifkan secara default.
- Implementasikan allowlist peer/prefix, max route-count delta, prefix-length checks, deny default route, bogon rejection, next-hop check, rate limits dan circuit breaker.
- Semua execute harus idempotent, tercatat, punya pre-check/post-check dan rollback.
- Jika belum aman/teruji, feature production harus disabled dengan penjelasan, bukan tombol palsu.

### 9. DDoS detection dan mitigation workflow
- Baseline dan anomaly signal berdasarkan bit/s, packet/s, protocol, port, target prefix/IP dan histori flow.
- Buat incident record dan severity/confidence.
- Tahap awal hanya alert + simulate candidate rule.
- FlowSpec/RTBH adapter boleh dibuat setelah lab tests: rule scope minimal, prefix allowlist, approval, expiry otomatis, post-check dan withdrawal/rollback.

### 10. Alert, incident, reporting
- Rule threshold/event untuk bandwidth, no flow received, device unreachable, interface down, BGP peer down/flap, probe degradation, anomaly dan collector health.
- Severity info/warning/major/critical, deduplication, suppression/maintenance window, acknowledge, assignment, notes dan resolution timeline.
- Notifikasi email/webhook opsional; core application tidak boleh bergantung pada SaaS.
- Report bandwidth, 95th percentile, interface/provider utilization, traffic by ASN/prefix, route performance, peer uptime, incidents dan change history.

### 11. Admin dan policy
- Sites/POPs, providers/ASN, routers, interfaces, collectors/exporters, probe targets, prefix allowlists, peer allowlists, scoring policy, thresholds, data retention, user roles, notification settings, feature flags dan audit.
- Secrets tidak boleh muncul pada log, audit payload, response API atau frontend. Encrypt at rest atau gunakan secret store lokal.

## Model data minimal

PostgreSQL: users, roles, sites, providers, devices, interfaces metadata, collectors, SNMP profiles, BGP peer metadata, probe targets, scoring policies, alerts, incidents, recommendations, change requests, approvals, execution history, notification settings, feature flags dan audit events.

ClickHouse: normalized flow records serta agregasi per time bucket. Setiap record harus menyimpan setidaknya timestamp, exporter, src/dst IP, src/dst port, protocol, packets, bytes, input/output interface bila ada, next-hop bila ada, sampling metadata dan source format.

Jangan menaruh volume raw flow besar ke PostgreSQL. Tambahkan migrations, index/order keys, TTL/retention dan contoh query yang dapat diulang.

## API minimum

Buat REST API versioned `/api/v1` dengan OpenAPI:
- `/auth/*`
- `/dashboard/summary`
- `/flows`, `/flows/top-talkers`, `/flows/traffic-matrix`
- `/devices`, `/devices/{id}/interfaces`, `/collectors`, `/collectors/{id}/health`
- `/bgp/peers`, `/bgp/routes`, `/bgp/events`
- `/probes/targets`, `/probes/results`
- `/recommendations`, `/recommendations/{id}/simulate`
- `/change-requests`, `/change-requests/{id}/approve`, `/.../execute`, `/.../rollback`
- `/alerts`, `/incidents`, `/reports/*`, `/admin/policies`, `/audit`

Semua endpoint harus menerapkan authentication, RBAC, pagination/range limits, validation, structured errors, dan tests.

## UI/UX

Buat desain orisinal yang profesional untuk NOC: dark mode dan light mode, layout sidebar, top status bar, responsive grid, data tables yang bisa dicari/disortir, filter yang konsisten, chart yang punya legend/unit, dan timestamp yang eksplisit. Prioritaskan keterbacaan operator saat incident. Jangan menyalin screenshot, layout pixel-perfect, logo atau aset Noction.

Menu utama: Overview, Traffic, Devices, Collectors, BGP, Path Quality, Optimization, Security, Alerts/Incidents, Reports, Administration.

## Acceptance criteria minimum

1. Fresh install dapat dijalankan mengikuti README dan Docker Compose.
2. Login dan RBAC benar-benar membatasi endpoint API.
3. Demo mode memiliki traffic simulator yang menghasilkan record nyata ke pipeline dan memiliki badge DEMO.
4. Flow fixture diuji otomatis; parser error tidak membuat collector crash.
5. Data Explorer, Top Talkers, traffic trend dan filter menghasilkan nilai yang dapat diverifikasi dari fixture.
6. SNMP agent/lab menghasilkan inventory serta interface stats dan menangani timeout.
7. BGP lab menghasilkan peer state dan route events; tidak ada klaim live tanpa sumber live.
8. Probe hasilnya disimpan; label provider hanya dipakai jika egress dipastikan.
9. Recommendation engine punya test deterministik, scoring yang terlihat, dan anti-oscillation.
10. Simulation tidak mengirim update apa pun ke router.
11. Route execution production tetap nonaktif pada fresh install.
12. Lab BGP test membuktikan announce, withdraw, pre/post-check dan rollback.
13. Semua tindakan sensitif tercatat di audit; secrets tidak terlihat di log.
14. Backup dan restore database diuji; dokumentasinya tersedia.
15. Fitur yang belum dibuat tidak ditampilkan seolah sudah berfungsi.

## Cara kerja yang harus diikuti

1. **Inspect** repo sekarang, stack, env dan status dependency terlebih dahulu. Jangan menimpa proyek yang sudah ada tanpa audit.
2. Buat `IMPLEMENTATION_PLAN.md`, `ARCHITECTURE.md`, dan ADR singkat untuk keputusan utama.
3. Buat backlog per fase dan kerjakan langsung, bukan hanya memberikan saran atau mockup.
4. **Phase 0-1:** project skeleton, auth/RBAC, schema/migrations, audit, app shell, Docker Compose, health checks.
5. **Phase 2:** flow collector, fixtures, ClickHouse, demo traffic simulator, first Data Explorer.
6. **Phase 3:** SNMP inventory/counters/alerts.
7. **Phase 4:** BGP visibility dan active probes.
8. **Phase 5:** scoring/recommendation engine dan route simulator.
9. **Phase 6:** isolated BGP lab tests dan rollback.
10. **Phase 7+:** production gates, FlowSpec/RTBH dan hardening hanya setelah tahap sebelumnya lulus.
11. Setiap fase harus menjalankan unit/integration/e2e tests, lint/typecheck, migrations dan build. Perbaiki error sebelum melanjutkan.
12. Setelah setiap fase, laporkan secara spesifik: file yang dibuat/diubah, command yang dijalankan, hasil test pass/fail, bagaimana menjalankan aplikasi, fitur live vs demo, serta keterbatasan nyata.

## Instruksi pertama: mulai sekarang

Mulai dengan audit workspace dan tulis rencana implementasi yang ringkas. Setelah itu **langsung implementasikan Phase 0 dan Phase 1 pada repo**, jangan berhenti di rencana. Bila repo kosong, scaffold aplikasi dan komponennya. Buat test dan README, jalankan build serta test, dan lanjutkan ke Phase 2 selama struktur fondasi sudah stabil. Jangan pernah menghubungkan sistem ke router produksi atau mengirim BGP changes selama development.

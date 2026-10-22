# ADR 0006: Production-Gated Routing Optimization, Mitigation (FlowSpec & RTBH), and Circuit Breaker

## Status
Accepted

## Konteks
Pada Phase 0–6, JDP Route Intelligence Platform telah berhasil mengimplementasikan pengumpulan telemetri aliran data (NetFlow/IPFIX/sFlow), polling SNMP, observasi BMP BGP, probing jalur aktif, mesin rekomendasi multivariat, dual approval change request, dan isolated BGP lab dengan automated rollback.

Tujuan Phase 7 adalah membangun kerangka eksekusi optimasi perutean dan mitigasi ancaman (FlowSpec RFC 8955/5575 dan RTBH RFC 7999) yang siap produksi namun **secara ketat dikunci di balik gerbang eksekusi (*production execution gate*)**. Sistem harus mencegah mutasi rute yang tidak sah atau berbahaya pada jaringan ISP produksi, menerapkan *controlled rollout*, *circuit breaker*, *emergency stop*, serta deteksi dan evaluasi kandidat mitigasi berbasis anomali trafik.

## Keputusan Arsitektur

### 1. Multi-Flag Execution Gate (Deny-by-Default)
- Variabel environment utama `ROUTING_EXECUTION_ENABLED=false` tetap dipertahankan sebagai kunci induk (*master lock*).
- Ditambahkan tiga feature flag granular independen yang juga berstatus `False` secara default:
  - `PRODUCTION_ROUTING_ENABLED=false`: Memblokir eksekusi rute unicast ke router produksi.
  - `FLOWSPEC_EXECUTION_ENABLED=false`: Memblokir inject rule FlowSpec ke router produksi.
  - `RTBH_EXECUTION_ENABLED=false`: Memblokir inject rule RTBH blackhole ke router produksi.
- Backend memeriksa 12 lapis verifikasi (*12-point Production Execution Gate*) sebelum operasi diizinkan:
  1. Feature flag operasi spesifik aktif secara eksplisit.
  2. Router target dan peer berada dalam inventaris aktif dan allowlist.
  3. Prefix dan atribut perubahan memenuhi kebijakan (*PrefixAllowlist*).
  4. Change Request memiliki persetujuan (*approval*) yang sah.
  5. Pemohon (*requester*) dilarang menyetujui perubahannya sendiri (*anti-self-approval*).
  6. Persetujuan ganda (*dual-approval*) terpenuhi jika diwajibkan oleh policy.
  7. Bukti pengujian lab terisolasi dan rollback valid (`lab_tested=True` dan `lab_test_run_id`).
  8. Telemetri rute dan path probe masih segar (*not stale*, $\le 180$ detik).
  9. Pre-check keselamatan lulus.
  10. Berada dalam jendela pemeliharaan (*change window*) dan batas rollout ($\le$ batas limit prefix).
  11. Subsistem audit trail siap mencatat secara persisten.
  12. Tidak ada operasi bertentangan yang sedang berjalan pada prefix/objek yang sama.

### 2. Pemisahan Adapter Secara Tegas
Sistem membedakan tiga interface adapter yang berdiri sendiri:
- **`SimulationAdapter`**: Menghitung dampak rute (*what-if delta*, estimasi pergeseran trafik) tanpa mutasi jaringan.
- **`BGPLabAdapter`**: Mengontrol BGP speaker terisolasi (GoBGP AS 65001 & AS 65002) di internal Docker network.
- **`ProductionBGPAdapter`**: Abstraksi koneksi perangkat produksi (Junos/Huawei/Mikrotik/Cisco). Pada Phase 7, adapter ini beroperasi dalam mode **dry-run / locked**, menolak eksekusi nyata, dan merekam rencana payload perintah tanpa mengirimkannya ke perangkat fisik.

Mesin rekomendasi dan workflow mitigasi dilarang memanggil shell, CLI internal, atau Netconf secara langsung.

### 3. Workflow Mitigasi Terpisah: FlowSpec vs RTBH
- **FlowSpec Mitigation (RFC 8955 / RFC 5575)**:
  - Kandidat ancaman (*ThreatCandidate*) dibentuk dari anomali trafik ClickHouse (lonjakan pps/bps, port scanning, SYN flood).
  - Skema rule bertipe ketat (*typed schema*): Source Prefix, Destination Prefix, Protocol, Port Range, TCP Flags, ICMP types.
  - Aksi mitigasi yang didukung: `rate_limit` (bps/pps), `discard`, `redirect_vrf`, `mark_dscp`.
  - Validasi: Tolak `0.0.0.0/0`, tolak rule terlalu luas tanpa filter port/protokol, validasi batas kompleksitas rule, dan wajib menyertakan TTL/waktu kedaluwarsa (*auto-expiry*).
- **RTBH Mitigation (RFC 7999)**:
  - Tindakan mitigasi berisiko tinggi yang mendrop seluruh trafik menuju host/subnet tujuan.
  - Validasi ketat panjang prefix: Hanya `/32` (IPv4 host) atau subnet pelanggan terdaftar yang diizinkan (misal `/28`–`/32`).
  - Tolak default route `0.0.0.0/0` dan `::/0`, bogon, serta martian.
  - Validasi BGP Blackhole Community (default RFC 7999 `65535:666` atau konfigurasi upstream ISP).
  - Wajib Dual Approval dari dua akun berwenang sebelum rule dapat dijadwalkan.
  - Wajib menyertakan batas durasi/kedaluwarsa otomatis dan rencana pemulihan (*withdrawal plan*).

### 4. Circuit Breaker dan Emergency Stop
- State machine Circuit Breaker: `CLOSED` (Normal) $\to$ `OPEN` (Terpicu / Operasi Diblokir) $\to$ `HALF_OPEN` (Uji Pemulihan Terbatas).
- Pemicu otomatis Circuit Breaker:
  - Kegagalan post-check berulang ($\ge 3$ kali).
  - Kegagalan automated rollback.
  - Hilangnya konektivitas adapter speaker.
  - Data telemetri menjadi basi (*stale*).
  - Pelanggaran batas volume perubahan per rollout.
- Dampak Circuit Breaker `OPEN`:
  - Seluruh permintaan eksekusi baru diblokir seketika.
  - Menerbitkan alert tingkat kritis pada dashboard dan audit log.
  - Mewajibkan intervensi manusia untuk melakukan telaah dan reset manual (`reset_circuit_breaker`).
- **Emergency Stop (Kill-Switch)**:
  - Endpoint global untuk menghentikan seketika penerimaan seluruh eksekusi baru tanpa mengubah status operasi yang sedang berlangsung menjadi sukses palsu.

### 5. Controlled Routing Rollout State Machine
Lifecycle perubahan routing diatur secara formal:
`Draft` $\to$ `Policy Validated` $\to$ `Lab Tested` $\to$ `Awaiting Approval` $\to$ `Approved` $\to$ `Scheduled` $\to$ `Pre-check` $\to$ `Executing` $\to$ `Post-check` $\to$ `Completed` (atau `Failed`, `Rollback Pending`, `Rolled Back`, `Needs Manual Review`, `Cancelled`, `Expired`).

## Konsekuensi
- **Positif**:
  - Jaringan produksi ISP 100% terlindungi dari salah konfigurasi, eksekusi rute liar, atau rule mitigasi yang merusak (*blackhole*) rute publik.
  - Seluruh kandidat mitigasi DDoS (FlowSpec & RTBH) terdokumentasi dengan bukti telemetri, preview rule terstruktur, masa kedaluwarsa, dan alur approval.
  - Kegagalan sistem otomatis memicu Circuit Breaker yang mengunci sistem sebelum dampak menyebar.
- **Batasan**:
  - Pada Phase 7, seluruh adapter produksi tetap berada dalam status terkunci / *dry-run* aman; eksekusi fisik ke router nyata memerlukan otorisasi operasional di masa mendatang.

# LAPORAN LENGKAP AUDIT KONSISTENSI KEBIJAKAN RTBH
## JDP Route Intelligence Platform — Controlled Acceptance Test

- **Proyek:** JDP Route Intelligence Platform
- **Cabang Git:** `uat-readiness-hardening`
- **Baseline Awal:** Commit `566bee4`
- **Commit Resolusi:** Commit `29c6ec7` (`fix(mitigation): align RTBH /24-/32 prefix bounds, allowlist validation, and UAT audit trail`)
- **Tanggal Audit:** 23 Oktober 2026
- **Status Guardrail Produksi:** `ROUTING_EXECUTION_ENABLED=false`, `PRODUCTION_ROUTING_ENABLED=false`, `FLOWSPEC_EXECUTION_ENABLED=false`, `RTBH_EXECUTION_ENABLED=false` (LOCKED 100%)

---

## 1. Latar Belakang & Masalah Ketidakkonsistenan

Seluruh 4 batch UAT telah dilaporkan selesai pada commit `566bee4`. Namun, ditemukan ketidakkonsistenan dokumentasi dan bukti uji terkait kebijakan **Remotely Triggered Black Hole (RTBH - RFC 7999)**:

1. **Dokumentasi Phase 7 & Spesifikasi:**
   - Menyebutkan bahwa rentang prefix IPv4 yang diizinkan untuk mitigasi RTBH adalah **/24 hingga /32**.
2. **Laporan UAT Batch 4 Awal:**
   - Menyebutkan bahwa mitigasi RTBH melakukan *penolakan terhadap subnet luas (/16, /24)*, sementara host route `/32` diterima.
3. **Isu Inti yang Diaudit:**
   - Apakah prefix `/24` seharusnya diterima atau ditolak?
   - Mengapa muncul klaim penolakan terhadap `/24` pada rangkuman UAT Batch 4 padahal validator kode menggunakan batas `< 24`?
   - Apakah validasi `PrefixAllowlist` telah ditegakkan pada alur kerja RTBH?

---

## 2. Hasil Audit Menyeluruh Lintas Komponen

Audit teknis dilakukan terhadap seluruh komponen sistem:

### 2.1. Validator Source Code & Skema Pydantic
- **`backend/app/schemas/mitigation.py` (`RTBHRuleCreate`):**
  - Validator kode awal:
    ```python
    if net.prefixlen < 24:
        raise ValueError(f"Prefix length /{net.prefixlen} is too broad for RTBH. Minimum allowed is /24, recommended /32.")
    ```
  - Secara logika matematika, `net.prefixlen == 24` bernilai `False` pada kondisi `< 24`, sehingga **/24 selalu diterima oleh validator**.
  - Subnet yang lebih luas dari `/24` (seperti `/16`, `/8`, atau default route `/0`) ditolak mutlak.
  - Namun, pada deskripsi field terdapat sisa teks draf lama: `description="Target host or subnet to blackhole (must be /32 or allowed /28-/32)"`.

### 2.2. Service Backend Mitigasi
- **`backend/app/services/mitigation_service.py` (`generate_rtbh_preview` & `create_rtbh_rule`):**
  - Pesan penolakan validator secara eksplisit menyatakan:
    `"REJECTED: Prefix length /{net.prefixlen} is too broad. RTBH only allowed for /24 to /32."`
  - Namun, fungsi `create_rtbh_rule` dan `generate_rtbh_preview` belum memvalidasi `PrefixAllowlist` aktif di database PostgreSQL, sehingga berpotensi menerima prefix di luar kepemilikan ISP jika tidak diblokir di layer selanjutnya.

### 2.3. Checklist Acceptance UAT & Bukti UAT Batch 4
- **`docs/runbooks/uat-acceptance-checklist.md` (Section 9 - UAT-MITIG-01):**
  - Pada tabel *Langkah Pengujian* butir 4 tertulis jelas:
    `Verifikasi penolakan terhadap subnet luas ($</24$).`
  - Namun, pada tabel *Actual Result* yang ditulis pasca pengujian, operator menuliskan:
    `Penolakan terhadap subnet luas (/16, /24) ditegakkan secara absolut, sementara host route /32 diterima.`
  - **Kesimpulan Akar Masalah:** Terjadi salah kutip (human error) saat operator merangkum notasi matematika `$</24$` menjadi teks deskriptif `(/16, /24)` karena mengasumsikan `/24` sebagai subnet biasa, tanpa memperhatikan operator ketaksamaan *strictly less than* ($<$).

### 2.4. Arsitektur & ADR (Architectural Decision Record)
- **`docs/adr/0006-production-gated-optimization-and-mitigation.md`:**
  - Pada butir 3 (*RTBH Mitigation*) tertulis draf awal: `(misal /28–/32)` yang belum diselaraskan dengan keputusan final arsitektur Phase 7 (`/24` hingga `/32`).

### 2.5. Dokumen Rencana & README
- **`IMPLEMENTATION_PLAN.md` (Tabel Phase 7):**
  - Sejak awal mendefinisikan: `RTBH RFC 7999 host blackhole workflow with mandatory dual-approval & /24-/32 prefix bounds`.
- **`README.md` (Tabel Fitur Baris 334):**
  - Sejak awal mencatat: `RTBH Mitigation Workflow: Berfungsi Penuh (RFC 7999 community 65535:666, validasi host /24-/32, penolakan subnet luas, mandatory dual-approval 2-langkah)`.

---

## 3. Penentuan Kebijakan Final

### Kebijakan Resmi yang Disepakati:
**Rentang prefix yang diizinkan untuk RTBH (RFC 7999) adalah `/24` hingga `/32` untuk IPv4, dengan kewajiban bahwa target prefix atau subnet induknya terdaftar aktif dalam `PrefixAllowlist`.**

### Rasionalisasi Teknis:
1. **Standar Global BGP & ISP Peering (RFC 7999):**
   - Dalam perutean Internet global dan pertukaran trafik antar-ISP/IXP, ukuran prefix terkecil yang diizinkan untuk dirutekan adalah `/24`.
   - Host route `/32` adalah rekomendasi utama (*recommended*) untuk men-drop trafik ke single victim host tanpa mengorbankan host lain dalam subnet pelanggan.
   - Namun, pada insiden serangan DDoS volumetrik masif yang menyerang seluruh rentang IP pelanggan (*subnet-wide flood*), operator NOC diizinkan secara sah untuk memblackhole seluruh subnet pelanggan terdaftar hingga batas `/24`.
2. **Perlindungan Terhadap Collateral Damage:**
   - Prefix yang lebih luas dari `/24` ($< /24$, seperti `/16` berisi 65.536 host atau `/8`) **dilarang keras** karena dapat menyebabkan pemadaman massal tidak disengaja.
   - Default route (`0.0.0.0/0` dan `::/0`) **dilarang mutlak**.
   - Prefix di luar `PrefixAllowlist` **dilarang mutlak** untuk mencegah pembajakan rute atau blackhole ilegal terhadap IP pihak ketiga.

---

## 4. Perubahan Source Code, Skema, dan Dokumentasi

Untuk menegakkan konsistensi 100%, perubahan berikut diimplementasikan dan dikomit:

1. **`backend/app/schemas/mitigation.py`:**
   - Memperbarui deskripsi `target_prefix` menjadi: `(allowed range /24 to /32 for IPv4, host /32 recommended)`.
   - Mempertegas validator Pydantic untuk IPv4 (rentang `/24`–`/32`) dan IPv6 (rentang `/64`–`/128`).
2. **`backend/app/services/mitigation_service.py`:**
   - Menambahkan verifikasi `PrefixAllowlist` di database (termasuk *subnet containment* via `net.subnet_of(an)`).
   - Menolak pembuatan rule (`HTTP 400 Bad Request`) dan menandai preview `INVALID` jika target prefix berada di luar allowlist aktif.
   - Menerapkan proteksi default route dan prefix bounds yang ketat pada `create_rtbh_rule` dan `create_flowspec_rule`.
3. **`backend/app/api/v1/endpoints/mitigation.py`:**
   - Menyuntikkan query `PrefixAllowlist` ke dalam endpoint preview `POST /api/v1/mitigation/rtbh/preview`.
4. **`backend/app/services/execution_gate.py`:**
   - Memperbarui Check 3 (Prefix & Policy Allowlist) agar memverifikasi subnet containment dan membatasi prefix RTBH pada rentang `/24`–`/32`.
5. **`backend/tests/test_mitigation_and_rollout.py`:**
   - Memperluas fungsi `test_rtbh_mitigation_dual_approval_and_prefix_guards` untuk menguji secara eksplisit kelima kondisi kebijakan.
6. **`scripts/uat_mitigation_verification.py`:**
   - Menambahkan pengujian Step 3b (`/24`), 3e (`::/0`), 3f (outside allowlist preview), dan 3g (outside allowlist creation rejection).
7. **`docs/adr/0006-production-gated-optimization-and-mitigation.md`:**
   - Menyelaraskan teks keputusan ADR 0006 poin 3 dengan rentang `/24` hingga `/32`.
8. **`docs/runbooks/uat-acceptance-checklist.md`:**
   - Memperbaiki ringkasan pada Section 9 (UAT-MITIG-01) *Actual Result* dan menambahkan jejak audit (*Audit Trail Catatan Koreksi Kebijakan RTBH*) pada *Catatan Operator*.
9. **`README.md`:**
   - Memperbarui ringkasan test agar mencerminkan validasi `/24-/32`, penolakan `/16`, default routes, allowlist check, dan dual approval.

---

## 5. Bukti Hasil Pengujian Terarah (Actual Test Results)

### 5.1. UAT Mitigation Acceptance Script
Perintah:
```powershell
& "C:\Users\permadi pratama\AppData\Local\Programs\pgAdmin 4\python\python.exe" scripts/uat_mitigation_verification.py
```
Hasil:
```text
[UAT-MITIG-01] === STEP-3: RTBH Rule Preview, /24-/32 Policy, & RFC 7999 Community Validation ===
  3a. Valid /32 RTBH Preview:
      - Validation Status: VALID
      - Community: 65535:666
      - Next-Hop: 192.0.2.1
      - BGP Update Payload: {"nlri": "103.145.2.14/32", "communities": ["65535:666"], "next_hop": "192.0.2.1", "action": "ANNOUNCE_BLACKHOLE", "expires_at": "2026-10-23T09:24:11.806272+00:00"}
  3b. Valid /24 RTBH Preview:
      - Validation Status: VALID
      - Prefix Length: /24
      - Is Host Route: False
  3c. Broad Subnet /16 RTBH Rejection: BLOCKED (Prefix length /16 is too broad for RTBH. Minimum allowed is /24, recommended /32.)
  3d. Default Route 0.0.0.0/0 RTBH Rejection: BLOCKED (Default route cannot be targeted for RTBH.)
  3e. Default Route ::/0 RTBH Rejection: BLOCKED (Default route cannot be targeted for RTBH.)
  3f. Outside Allowlist RTBH Rejection: BLOCKED (["REJECTED: Target prefix '198.51.100.99/32' is not in the active PrefixAllowlist."])
  3g. Outside Allowlist Creation: BLOCKED (GUARDRAIL REJECTION: Target prefix '198.51.100.99/32' is outside the active PrefixAllowlist.)

TOTAL CHECKS: 7 | PASSED: 7 | FAILED: 0
OVERALL STATUS: 100% PASS — READY FOR SIGN-OFF
```

### 5.2. Pytest Unit & Integration Tests (Mitigasi & Rollout)
Perintah:
```powershell
& "C:\Users\permadi pratama\AppData\Local\Programs\pgAdmin 4\python\python.exe" -m pytest backend/tests/test_mitigation_and_rollout.py -v
```
Hasil:
```text
backend\tests\test_mitigation_and_rollout.py::test_production_execution_flags_locked_by_default PASSED [ 12%]
backend\tests\test_mitigation_and_rollout.py::test_production_adapter_dry_run_and_execution_lock PASSED [ 25%]
backend\tests\test_mitigation_and_rollout.py::test_12_point_execution_gate_evaluator PASSED [ 37%]
backend\tests\test_mitigation_and_rollout.py::test_threat_candidate_lifecycle PASSED [ 50%]
backend\tests\test_mitigation_and_rollout.py::test_flowspec_preview_and_rule_lifecycle PASSED [ 62%]
backend\tests\test_mitigation_and_rollout.py::test_rtbh_mitigation_dual_approval_and_prefix_guards PASSED [ 75%]
backend\tests\test_mitigation_and_rollout.py::test_controlled_rollout_lifecycle_and_batch_limits PASSED [ 87%]
backend\tests\test_mitigation_and_rollout.py::test_circuit_breaker_and_emergency_stop PASSED [100%]
============================== 8 passed in 26.75s ==============================
```

### 5.3. Pytest Regression Tests (Guardrails, BGP Lab, Recommendations & Simulator)
Perintah:
```powershell
& "C:\Users\permadi pratama\AppData\Local\Programs\pgAdmin 4\python\python.exe" -m pytest backend/tests/test_guardrails.py backend/tests/test_bgp_lab.py backend/tests/test_recommendation_and_simulator.py -v
```
Hasil:
```text
======================= 40 passed in 106.49s (0:01:46) ========================
```

---

## 6. Verifikasi Guardrail & Integritas Lingkungan Produksi

1. **Nilai Execution Flags Aktual:**
   - `ROUTING_EXECUTION_ENABLED = False`
   - `PRODUCTION_ROUTING_ENABLED = False`
   - `FLOWSPEC_EXECUTION_ENABLED = False`
   - `RTBH_EXECUTION_ENABLED = False`
   - `BGP_LAB_ENABLED = False`
2. **Kepatuhan Isolasi:**
   - Tidak ada route update, BGP community, atau FlowSpec rule yang dikirimkan ke router fisik atau peer manapun.
   - Adapter beroperasi dalam status `LOCKED_DRY_RUN`.
   - Database development (`jdp_route_intel`, `jdp_flow_analytics`) tidak tersentuh.
   - Volume Docker tidak ada yang dihapus atau di-reset.

---

## 7. Catatan Jejak Audit Git

- **Branch:** `uat-readiness-hardening`
- **Commit ID:** `29c6ec7`
- **Pesan Commit:** `fix(mitigation): align RTBH /24-/32 prefix bounds, allowlist validation, and UAT audit trail`
- **Daftar Berkas Terubah:**
  1. `README.md`
  2. `backend/app/api/v1/endpoints/mitigation.py`
  3. `backend/app/schemas/mitigation.py`
  4. `backend/app/services/execution_gate.py`
  5. `backend/app/services/mitigation_service.py`
  6. `backend/tests/test_mitigation_and_rollout.py`
  7. `docs/adr/0006-production-gated-optimization-and-mitigation.md`
  8. `docs/runbooks/uat-acceptance-checklist.md`
  9. `scripts/uat_mitigation_verification.py`
- **Status Working Tree:** Bersih (`nothing to commit, working tree clean`).

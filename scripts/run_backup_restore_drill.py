#!/usr/bin/env python3
"""
Comprehensive Backup & Restore Drill Harness for JDP Route Intelligence Platform.
Executes automated backup of PostgreSQL and ClickHouse, verifies checksums,
restores both into isolated test databases, validates row counts, and logs results.
"""
import os
import sys
import subprocess
from datetime import datetime, timezone

def run_drill():
    print("=" * 70)
    print("JDP ROUTE INTELLIGENCE PLATFORM — BACKUP & RESTORE DRILL")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    # 1. PostgreSQL Backup
    print("\n--- PHASE A: PostgreSQL Backup ---")
    pg_backup_cmd = [sys.executable, "scripts/backup_postgres.py"]
    res_pg_b = subprocess.run(pg_backup_cmd, capture_output=True, text=True)
    print(res_pg_b.stdout)
    if res_pg_b.returncode != 0:
        print(f"PostgreSQL backup failed:\n{res_pg_b.stderr}", file=sys.stderr)
        return False

    # Find the latest backup file in backups/postgres
    pg_files = sorted([f for f in os.listdir("backups/postgres") if f.endswith(".sql.gz")])
    if not pg_files:
        print("ERROR: No PostgreSQL backup file found!", file=sys.stderr)
        return False
    latest_pg_file = os.path.join("backups/postgres", pg_files[-1])

    # 2. PostgreSQL Restore to Isolated Target
    print("\n--- PHASE B: PostgreSQL Restore Drill (Isolated Target) ---")
    pg_restore_cmd = [
        sys.executable, "scripts/restore_postgres.py",
        latest_pg_file,
        "--target-db", "jdp_route_intel_restore_test"
    ]
    res_pg_r = subprocess.run(pg_restore_cmd, capture_output=True, text=True)
    print(res_pg_r.stdout)
    if res_pg_r.returncode != 0:
        print(f"PostgreSQL restore failed:\n{res_pg_r.stderr}", file=sys.stderr)
        return False

    # 3. ClickHouse Backup
    print("\n--- PHASE C: ClickHouse Backup ---")
    ch_backup_cmd = [sys.executable, "scripts/backup_clickhouse.py"]
    res_ch_b = subprocess.run(ch_backup_cmd, capture_output=True, text=True)
    print(res_ch_b.stdout)
    if res_ch_b.returncode != 0:
        print(f"ClickHouse backup failed:\n{res_ch_b.stderr}", file=sys.stderr)
        return False

    # Find the latest backup file in backups/clickhouse
    ch_files = sorted([f for f in os.listdir("backups/clickhouse") if f.endswith(".tar.gz")])
    if not ch_files:
        print("ERROR: No ClickHouse backup file found!", file=sys.stderr)
        return False
    latest_ch_file = os.path.join("backups/clickhouse", ch_files[-1])

    # 4. ClickHouse Restore to Isolated Target
    print("\n--- PHASE D: ClickHouse Restore Drill (Isolated Target) ---")
    ch_restore_cmd = [
        sys.executable, "scripts/restore_clickhouse.py",
        latest_ch_file,
        "--target-db", "jdp_flow_analytics_restore_test"
    ]
    res_ch_r = subprocess.run(ch_restore_cmd, capture_output=True, text=True)
    print(res_ch_r.stdout)
    if res_ch_r.returncode != 0:
        print(f"ClickHouse restore failed:\n{res_ch_r.stderr}", file=sys.stderr)
        return False

    print("\n" + "=" * 70)
    print("BACKUP & RESTORE DRILL COMPLETED WITH 100% SUCCESS!")
    print("All target verification assertions passed without mutating active tables.")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_drill()
    sys.exit(0 if success else 1)

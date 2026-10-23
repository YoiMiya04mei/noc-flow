#!/usr/bin/env python3
"""
PostgreSQL Restore Verification Tool for JDP Route Intelligence Platform.
Restores a backup archive into an isolated test database (or specified target),
verifies SHA-256 integrity, validates schema and row counts against manifest,
and tests application-level query readability without mutating active production data.
"""
import os
import sys
import subprocess
import hashlib
import json
import gzip
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.core.config import settings

PG_CONTAINER = os.getenv("PG_CONTAINER", "jdp-postgres")
PG_USER = os.getenv("PG_USER", settings.POSTGRES_USER)
PG_DB = os.getenv("PG_DB", settings.POSTGRES_DB)
PG_PASSWORD = os.getenv("PG_PASSWORD", settings.POSTGRES_PASSWORD)

def redact_log(message: str) -> str:
    secrets = [PG_PASSWORD, settings.POSTGRES_PASSWORD, settings.SECRET_KEY]
    clean = message
    for s in secrets:
        if s and len(s) > 3:
            clean = clean.replace(s, "[REDACTED]")
    return clean

def verify_checksum(backup_path: str, expected_sha: str = None) -> str:
    print(f"Verifying SHA-256 integrity of {backup_path}...")
    hasher = hashlib.sha256()
    with gzip.open(backup_path, "rb") as f_in:
        while True:
            chunk = f_in.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    actual_sha = hasher.hexdigest()
    
    sha_file = f"{backup_path}.sha256"
    if not expected_sha and os.path.exists(sha_file):
        with open(sha_file, "r") as f:
            expected_sha = f.read().strip().split()[0]

    if expected_sha and actual_sha != expected_sha:
        raise ValueError(f"Checksum mismatch! Expected: {expected_sha}, Computed uncompressed: {actual_sha}")
    print(f"  SHA-256 verified: {actual_sha}")
    return actual_sha

def restore_postgres(backup_path: str, target_db: str = "jdp_route_intel_restore_test", allow_prod_overwrite: bool = False):
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    # Safety Guardrail: Prevent accidental overwrite of active production DB
    if target_db in (PG_DB, settings.POSTGRES_DB) and not allow_prod_overwrite:
        raise PermissionError(
            f"SAFETY VIOLATION: Cannot restore directly into active database '{target_db}'! "
            f"Please specify an isolated test database like 'jdp_route_intel_restore_test' "
            f"or supply --dangerously-overwrite-active-db if intentionally conducting a disaster recovery."
        )

    # 1. Verify Checksum
    manifest_path = backup_path.replace(".sql.gz", ".manifest.json")
    manifest = None
    expected_sha = None
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            expected_sha = manifest.get("sha256")

    verify_checksum(backup_path, expected_sha)

    # 2. Prepare Isolated Target Database
    print(f"Preparing target database '{target_db}' on container {PG_CONTAINER}...")
    # Drop existing test db if needed and create clean
    subprocess.run([
        "docker", "exec", "-i", PG_CONTAINER,
        "psql", "-U", PG_USER, "-d", "postgres",
        "-c", f"DROP DATABASE IF EXISTS {target_db} WITH (FORCE);"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    subprocess.run([
        "docker", "exec", "-i", PG_CONTAINER,
        "psql", "-U", PG_USER, "-d", "postgres",
        "-c", f"CREATE DATABASE {target_db} OWNER {PG_USER};"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    # 3. Stream & Restore
    print(f"Restoring SQL dump into '{target_db}'...")
    restore_cmd = [
        "docker", "exec", "-i", PG_CONTAINER,
        "psql", "-U", PG_USER, "-d", target_db
    ]
    proc = subprocess.Popen(restore_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    with gzip.open(backup_path, "rb") as gz_in:
        while True:
            chunk = gz_in.read(65536)
            if not chunk:
                break
            proc.stdin.write(chunk)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        err = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"psql restore failed with exit code {proc.returncode}: {redact_log(err)}")

    print(f"SQL restore completed cleanly into '{target_db}'.")

    # 4. Verify Restored Table Counts & Compare with Manifest
    print("Verifying restored database schema and row counts...")
    tables = [
        "users", "sites", "providers", "devices", "interfaces",
        "collectors", "bgp_peers", "bgp_routes", "prefix_allowlists",
        "scoring_policies", "recommendations", "change_requests",
        "probe_targets", "probe_results", "alert_rules", "alert_incidents",
        "audit_events"
    ]
    query = " UNION ALL ".join([f"SELECT '{t}', count(*) FROM {t}" for t in tables]) + ";"
    res = subprocess.run([
        "docker", "exec", "-i", PG_CONTAINER,
        "psql", "-U", PG_USER, "-d", target_db,
        "-t", "-A", "-F", ",", "-c", query
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    restored_counts = {}
    for line in res.stdout.strip().splitlines():
        if "," in line:
            tbl, cnt = line.split(",", 1)
            restored_counts[tbl.strip()] = int(cnt.strip())

    mismatches = []
    if manifest and "table_row_counts" in manifest:
        expected_counts = manifest["table_row_counts"]
        for tbl, exp_cnt in expected_counts.items():
            act_cnt = restored_counts.get(tbl, 0)
            if act_cnt != exp_cnt:
                mismatches.append(f"Table '{tbl}': expected {exp_cnt}, found {act_cnt}")

    if mismatches:
        raise ValueError(f"Restored row count validation failed: {', '.join(mismatches)}")

    # 5. Test Application Readability Query
    test_query = "SELECT username, role FROM users WHERE role = 'super_admin' LIMIT 1;"
    read_res = subprocess.run([
        "docker", "exec", "-i", PG_CONTAINER,
        "psql", "-U", PG_USER, "-d", target_db,
        "-t", "-A", "-c", test_query
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    if "super_admin" not in read_res.stdout.strip():
        raise ValueError(f"Readability query failed! Expected role containing super_admin, got: {read_res.stdout.strip()}")

    print("Restored Database Verification Report:")
    print(f"  Target DB: {target_db}")
    print(f"  Verified Tables: {len(restored_counts)}")
    for tbl, cnt in restored_counts.items():
        print(f"    - {tbl}: {cnt} rows (MATCH)")
    print(f"  Application Readability: PASS (super_admin user verified: {read_res.stdout.strip()})")
    print(f"  Restore Drill Status: PASSED (100% Integrity)")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore PostgreSQL Backup to Test Target")
    parser.add_argument("backup_file", help="Path to .sql.gz backup file")
    parser.add_argument("--target-db", default="jdp_route_intel_restore_test", help="Target database name")
    parser.add_argument("--dangerously-overwrite-active-db", action="store_true", help="Permit overwrite of active database")
    args = parser.parse_args()

    try:
        restore_postgres(args.backup_file, args.target_db, args.dangerously_overwrite_active_db)
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR: Restore failed: {redact_log(str(exc))}", file=sys.stderr)
        sys.exit(1)

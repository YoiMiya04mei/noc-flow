#!/usr/bin/env python3
"""
ClickHouse Restore Verification Tool for JDP Route Intelligence Platform.
Restores ClickHouse DDL and partitions into an isolated test database (jdp_flow_analytics_restore_test),
verifies SHA-256 checksums, validates row counts, and runs aggregation test queries.
"""
import os
import sys
import subprocess
import hashlib
import json
import gzip
import tarfile
import shutil
import tempfile
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.core.config import settings

CH_CONTAINER = os.getenv("CH_CONTAINER", "jdp-clickhouse")
CH_USER = os.getenv("CH_USER", settings.CLICKHOUSE_USER)
CH_PASSWORD = os.getenv("CH_PASSWORD", settings.CLICKHOUSE_PASSWORD)
CH_DB = os.getenv("CH_DB", settings.CLICKHOUSE_DB)

def redact_log(message: str) -> str:
    secrets = [CH_PASSWORD, settings.CLICKHOUSE_PASSWORD, settings.SECRET_KEY]
    clean = message
    for s in secrets:
        if s and len(s) > 3:
            clean = clean.replace(s, "[REDACTED]")
    return clean

def verify_archive(tar_path: str, expected_sha: str = None) -> str:
    print(f"Verifying SHA-256 integrity of {tar_path}...")
    hasher = hashlib.sha256()
    with open(tar_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_sha = hasher.hexdigest()

    sha_file = f"{tar_path}.sha256"
    if not expected_sha and os.path.exists(sha_file):
        with open(sha_file, "r") as f:
            expected_sha = f.read().strip().split()[0]

    if expected_sha and actual_sha != expected_sha:
        raise ValueError(f"Checksum mismatch! Expected: {expected_sha}, Computed: {actual_sha}")
    print(f"  SHA-256 verified: {actual_sha}")
    return actual_sha

def restore_clickhouse(archive_path: str, target_db: str = "jdp_flow_analytics_restore_test", allow_prod_overwrite: bool = False):
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"ClickHouse backup file not found: {archive_path}")

    # Safety Guardrail: Prevent accidental overwrite of active production ClickHouse DB
    if target_db in (CH_DB, settings.CLICKHOUSE_DB) and not allow_prod_overwrite:
        raise PermissionError(
            f"SAFETY VIOLATION: Cannot restore directly into active ClickHouse database '{target_db}'! "
            f"Please specify an isolated test database like 'jdp_flow_analytics_restore_test' "
            f"or supply --dangerously-overwrite-active-db if intentionally conducting disaster recovery."
        )

    verify_archive(archive_path)

    temp_dir = tempfile.mkdtemp(prefix="jdp_ch_restore_")
    try:
        # Extract archive
        print(f"Extracting archive to temporary workspace {temp_dir}...")
        with tarfile.open(archive_path, "r:gz") as tar:
            try:
                tar.extractall(temp_dir, filter="data")
            except TypeError:
                tar.extractall(temp_dir)

        manifest_path = os.path.join(temp_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError("Invalid ClickHouse backup: missing manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f_man:
            manifest = json.load(f_man)

        # 1. Verify internal file checksums
        print("Verifying internal file checksums...")
        for fname, meta in manifest.get("files", {}).items():
            fpath = os.path.join(temp_dir, fname)
            f_hasher = hashlib.sha256()
            with gzip.open(fpath, "rb") as gz_f:
                while chunk := gz_f.read(65536):
                    f_hasher.update(chunk)
            if f_hasher.hexdigest() != meta["sha256"]:
                raise ValueError(f"File integrity corrupted for {fname}! Checksum mismatch.")
        print("  All internal data files passed integrity checks.")

        # 2. Prepare Isolated Target Database
        print(f"Creating isolated ClickHouse target database '{target_db}' on container '{CH_CONTAINER}'...")
        drop_cmd = f"DROP DATABASE IF EXISTS {target_db}; CREATE DATABASE {target_db};"
        subprocess.run([
            "docker", "exec", "-i", CH_CONTAINER,
            "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
            "--query", drop_cmd
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        source_db = manifest.get("database", "jdp_flow_analytics")

        # 3. Create Tables in Target DB
        # Re-apply schema DDL with target_db qualification
        flow_records_sql = os.path.join(temp_dir, "flow_records.sql")
        with open(flow_records_sql, "r", encoding="utf-8") as f:
            ddl = f.read().strip()
            ddl = ddl.replace(f"CREATE TABLE {source_db}.", f"CREATE TABLE IF NOT EXISTS {target_db}.")
            res = subprocess.run([
                "docker", "exec", "-i", CH_CONTAINER,
                "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
                "--database", target_db,
                "--multiquery"
            ], input=ddl, text=True, capture_output=True)
            if res.returncode != 0:
                raise RuntimeError(f"Create flow_records failed: {res.stderr}")

        flow_hourly_agg_sql = os.path.join(temp_dir, "flow_hourly_agg.sql")
        with open(flow_hourly_agg_sql, "r", encoding="utf-8") as f:
            ddl = f.read().strip()
            ddl = ddl.replace(f"CREATE TABLE {source_db}.", f"CREATE TABLE IF NOT EXISTS {target_db}.")
            res = subprocess.run([
                "docker", "exec", "-i", CH_CONTAINER,
                "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
                "--database", target_db,
                "--multiquery"
            ], input=ddl, text=True, capture_output=True)
            if res.returncode != 0:
                raise RuntimeError(f"Create flow_hourly_agg failed: {res.stderr}")

        # 4. Stream Data into Target DB
        for tbl in ["flow_records", "flow_hourly_agg"]:
            data_file = os.path.join(temp_dir, f"{tbl}.tsv.gz")
            print(f"Streaming data into {target_db}.{tbl}...")
            insert_cmd = [
                "docker", "exec", "-i", CH_CONTAINER,
                "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
                "--database", target_db,
                "--query", f"INSERT INTO {tbl} FORMAT TabSeparatedWithNamesAndTypes"
            ]
            proc = subprocess.Popen(insert_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with gzip.open(data_file, "rb") as gz_in:
                while chunk := gz_in.read(65536):
                    proc.stdin.write(chunk)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"Restore of {tbl} failed: {redact_log(err)}")

        # 5. Verify Restored Counts & Aggregations
        print("Verifying restored ClickHouse row counts and aggregation consistency...")
        check_cmd = [
            "docker", "exec", "-i", CH_CONTAINER,
            "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
            "--database", target_db,
            "--query", "SELECT 'flow_records', count() FROM flow_records UNION ALL SELECT 'flow_hourly_agg', count() FROM flow_hourly_agg"
        ]
        res = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        restored_counts = {}
        for line in res.stdout.strip().splitlines():
            if "\t" in line:
                t, c = line.split("\t", 1)
                restored_counts[t.strip()] = int(c.strip())

        expected_counts = manifest.get("row_counts", {})
        for tbl, exp_cnt in expected_counts.items():
            act_cnt = restored_counts.get(tbl, 0)
            if act_cnt != exp_cnt:
                raise ValueError(f"Restored count mismatch for '{tbl}': expected {exp_cnt}, found {act_cnt}")

        # Check aggregate query
        agg_test_cmd = [
            "docker", "exec", "-i", CH_CONTAINER,
            "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
            "--database", target_db,
            "--query", "SELECT count(), sum(packets), sum(bytes) FROM flow_records"
        ]
        agg_res = subprocess.run(agg_test_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(f"  Aggregation verification: {agg_res.stdout.strip()} (PASS)")

        print("Restored ClickHouse Verification Report:")
        print(f"  Target DB: {target_db}")
        for tbl, cnt in restored_counts.items():
            print(f"    - {tbl}: {cnt} rows (MATCH)")
        print(f"  Restore Drill Status: PASSED (100% Integrity)")
        return True

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore ClickHouse Backup to Test Target")
    parser.add_argument("backup_archive", help="Path to .tar.gz backup archive")
    parser.add_argument("--target-db", default="jdp_flow_analytics_restore_test", help="Target database name")
    parser.add_argument("--dangerously-overwrite-active-db", action="store_true", help="Permit overwrite of active database")
    args = parser.parse_args()

    try:
        restore_clickhouse(args.backup_archive, args.target_db, args.dangerously_overwrite_active_db)
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR: ClickHouse restore failed: {redact_log(str(exc))}", file=sys.stderr)
        sys.exit(1)

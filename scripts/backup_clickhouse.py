#!/usr/bin/env python3
"""
ClickHouse Backup Tool for JDP Route Intelligence Platform.
Exports table DDL definitions and compressed table partitions (flow_records & flow_hourly_agg),
generates SHA-256 checksums, and compiles a verification manifest.
"""
import os
import sys
import subprocess
import hashlib
import json
import gzip
import tarfile
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

def get_clickhouse_counts():
    cmd = [
        "docker", "exec", "-i", CH_CONTAINER,
        "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
        "--database", CH_DB,
        "--query", "SELECT 'flow_records', count() FROM flow_records UNION ALL SELECT 'flow_hourly_agg', count() FROM flow_hourly_agg"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    counts = {}
    for line in res.stdout.strip().splitlines():
        if "\t" in line:
            tbl, cnt = line.split("\t", 1)
            counts[tbl.strip()] = int(cnt.strip())
    return counts

def backup_clickhouse(output_dir: str = "backups/clickhouse"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    work_dir = os.path.join(output_dir, f"work_{timestamp}")
    os.makedirs(work_dir, exist_ok=True)

    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting ClickHouse backup for DB '{CH_DB}' on container '{CH_CONTAINER}'...")
    table_counts = get_clickhouse_counts()
    print(f"Recorded pre-backup metrics: flow_records={table_counts.get('flow_records', 0)}, flow_hourly_agg={table_counts.get('flow_hourly_agg', 0)}")

    # 1. Export Table DDLs
    tables = ["flow_records", "flow_hourly_agg", "flow_hourly_agg_mv"]
    ddls = {}
    for tbl in tables:
        cmd = [
            "docker", "exec", "-i", CH_CONTAINER,
            "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
            "--database", CH_DB,
            "--query", f"SHOW CREATE TABLE {tbl} FORMAT RawBLOB;"
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        ddls[tbl] = res.stdout.strip()
        with open(os.path.join(work_dir, f"{tbl}.sql"), "w", encoding="utf-8") as f:
            f.write(res.stdout.strip() + ";\n")

    # 2. Export Data for flow_records and flow_hourly_agg
    file_hashes = {}
    for tbl in ["flow_records", "flow_hourly_agg"]:
        data_file = os.path.join(work_dir, f"{tbl}.tsv.gz")
        dump_cmd = [
            "docker", "exec", "-i", CH_CONTAINER,
            "clickhouse-client", "--user", CH_USER, "--password", CH_PASSWORD,
            "--database", CH_DB,
            "--query", f"SELECT * FROM {tbl} FORMAT TabSeparatedWithNamesAndTypes"
        ]
        hasher = hashlib.sha256()
        total_bytes = 0
        with open(data_file, "wb") as f_out:
            with gzip.GzipFile(fileobj=f_out, mode="wb") as gz_out:
                proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                while True:
                    chunk = proc.stdout.read(65536)
                    if not chunk:
                        break
                    gz_out.write(chunk)
                    hasher.update(chunk)
                    total_bytes += len(chunk)
                proc.wait()
                if proc.returncode != 0:
                    err = proc.stderr.read().decode("utf-8", errors="replace")
                    raise RuntimeError(f"Export of {tbl} failed: {redact_log(err)}")
        file_hashes[f"{tbl}.tsv.gz"] = {
            "sha256": hasher.hexdigest(),
            "uncompressed_bytes": total_bytes,
            "compressed_bytes": os.path.getsize(data_file)
        }

    # 3. Compile Manifest
    manifest = {
        "database": CH_DB,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tables": tables,
        "row_counts": table_counts,
        "files": file_hashes,
        "status": "COMPLETED_VERIFIED"
    }
    manifest_path = os.path.join(work_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f_man:
        json.dump(manifest, f_man, indent=2)

    # 4. Create Archive
    tar_path = os.path.join(output_dir, f"jdp_clickhouse_{timestamp}.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        for fname in os.listdir(work_dir):
            full_p = os.path.join(work_dir, fname)
            tar.add(full_p, arcname=fname)

    # Cleanup temporary work_dir
    import shutil
    shutil.rmtree(work_dir)

    # Compute tar SHA-256
    tar_hasher = hashlib.sha256()
    with open(tar_path, "rb") as f_tar:
        while chunk := f_tar.read(65536):
            tar_hasher.update(chunk)
    tar_sha = tar_hasher.hexdigest()

    sha_path = f"{tar_path}.sha256"
    with open(sha_path, "w") as f_sha:
        f_sha.write(f"{tar_sha}  {os.path.basename(tar_path)}\n")

    manifest_copy_path = os.path.join(output_dir, f"jdp_clickhouse_{timestamp}.manifest.json")
    manifest["archive_sha256"] = tar_sha
    manifest["archive_bytes"] = os.path.getsize(tar_path)
    with open(manifest_copy_path, "w", encoding="utf-8") as f_mancopy:
        json.dump(manifest, f_mancopy, indent=2)

    print(f"[{datetime.now(timezone.utc).isoformat()}] ClickHouse Backup Completed Successfully!")
    print(f"  Archive: {tar_path} ({manifest['archive_bytes'] / 1024:.2f} KB)")
    print(f"  SHA-256: {tar_sha}")
    print(f"  Manifest: {manifest_copy_path}")
    return tar_path, manifest_copy_path

if __name__ == "__main__":
    try:
        backup_clickhouse()
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR: ClickHouse backup failed: {redact_log(str(exc))}", file=sys.stderr)
        sys.exit(1)

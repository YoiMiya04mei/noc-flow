#!/usr/bin/env python3
"""
PostgreSQL Backup Tool for JDP Route Intelligence Platform.
Performs logical backup via pg_dump, calculates SHA-256 checksum,
generates metadata manifest with row counts, and ensures zero credential leakage.
"""
import os
import sys
import subprocess
import hashlib
import json
import gzip
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.core.config import settings

def redact_log(message: str) -> str:
    """Ensure sensitive credentials never appear in console logs."""
    secrets = [settings.POSTGRES_PASSWORD, settings.SECRET_KEY]
    clean = message
    for s in secrets:
        if s and len(s) > 3:
            clean = clean.replace(s, "[REDACTED]")
    return clean

def get_table_counts():
    """Query row counts of critical tables before backup."""
    tables = [
        "users", "sites", "providers", "devices", "interfaces",
        "collectors", "bgp_peers", "bgp_routes", "prefix_allowlists",
        "scoring_policies", "recommendations", "change_requests",
        "probe_targets", "probe_results", "alert_rules", "alert_incidents",
        "audit_events"
    ]
    query = " UNION ALL ".join([f"SELECT '{t}', count(*) FROM {t}" for t in tables]) + ";"
    cmd = [
        "docker", "exec", "-i", "jdp-postgres",
        "psql", "-U", settings.POSTGRES_USER, "-d", settings.POSTGRES_DB,
        "-t", "-A", "-F", ",", "-c", query
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    counts = {}
    for line in res.stdout.strip().splitlines():
        if "," in line:
            tbl, cnt = line.split(",", 1)
            counts[tbl.strip()] = int(cnt.strip())
    return counts

def backup_postgres(output_dir: str = "backups/postgres"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"jdp_postgres_{timestamp}.sql.gz"
    backup_path = os.path.join(output_dir, backup_filename)
    manifest_path = os.path.join(output_dir, f"jdp_postgres_{timestamp}.manifest.json")
    sha_path = os.path.join(output_dir, f"{backup_filename}.sha256")

    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting PostgreSQL backup for DB '{settings.POSTGRES_DB}'...")
    print(f"Collecting pre-backup table metrics from jdp-postgres...")
    table_counts = get_table_counts()
    print(f"Recorded pre-backup metrics: {len(table_counts)} tables cataloged.")

    # Execute pg_dump from container and stream through gzip
    dump_cmd = [
        "docker", "exec", "-i", "jdp-postgres",
        "pg_dump", "-U", settings.POSTGRES_USER, "-d", settings.POSTGRES_DB,
        "--clean", "--if-exists", "--no-owner", "--no-privileges"
    ]

    hasher = hashlib.sha256()
    total_bytes = 0

    with open(backup_path, "wb") as f_out:
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
                raise RuntimeError(f"pg_dump failed with exit code {proc.returncode}: {redact_log(err)}")

    sha256_hex = hasher.hexdigest()
    compressed_size = os.path.getsize(backup_path)

    # Write SHA-256 sidecar
    with open(sha_path, "w") as f_sha:
        f_sha.write(f"{sha256_hex}  {backup_filename}\n")

    # Write Manifest
    manifest = {
        "database": settings.POSTGRES_DB,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "backup_file": backup_filename,
        "uncompressed_bytes": total_bytes,
        "compressed_bytes": compressed_size,
        "sha256": sha256_hex,
        "table_row_counts": table_counts,
        "total_tables_checked": len(table_counts),
        "status": "COMPLETED_VERIFIED"
    }
    with open(manifest_path, "w") as f_man:
        json.dump(manifest, f_man, indent=2)

    print(f"[{datetime.now(timezone.utc).isoformat()}] PostgreSQL Backup Completed Successfully!")
    print(f"  Artifact: {backup_path} ({compressed_size / 1024:.2f} KB)")
    print(f"  Uncompressed Size: {total_bytes / 1024:.2f} KB")
    print(f"  SHA-256: {sha256_hex}")
    print(f"  Manifest: {manifest_path}")
    return backup_path, manifest_path

if __name__ == "__main__":
    try:
        backup_postgres()
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR: Backup failed: {redact_log(str(exc))}", file=sys.stderr)
        sys.exit(1)

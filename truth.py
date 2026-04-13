#!/usr/bin/env python3
"""
Load ground truth entries from config.toml into the database.
Resolves device_id by MAC address. Safe to re-run — upserts existing rows.

Usage:
    python truth.py
"""

import json
import sys
from datetime import datetime, timezone

from db import ensure_db, get_connection, load_config


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main():
    ensure_db()
    config = load_config()
    entries = config.get("truth", [])

    if not entries:
        print("No truth entries found in config.toml")
        sys.exit(0)

    con = get_connection()

    for entry in entries:
        mac = entry.get("mac", "").strip()
        ip  = entry.get("ip", "").strip()

        if not mac:
            print(f"  SKIP  missing mac — {entry}")
            continue

        row = con.execute("SELECT id, device_code FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row is None:
            print(f"  SKIP  no device found with mac={mac} (ip={ip}) — run ingest.py first")
            continue

        device_id   = row["id"]
        device_code = row["device_code"]
        accepted_cpes_json = json.dumps(entry.get("accepted_cpes", []))
        ts = now()

        existing = con.execute(
            "SELECT id FROM ground_truth WHERE device_id = ?", (device_id,)
        ).fetchone()

        if existing:
            con.execute(
                """
                UPDATE ground_truth SET
                    true_vendor           = ?,
                    true_product          = ?,
                    true_firmware_version = ?,
                    accepted_cpes_json    = ?,
                    rubric_version        = ?,
                    label_status          = ?,
                    notes                 = ?,
                    updated_at            = ?
                WHERE device_id = ?
                """,
                (
                    entry.get("true_vendor"),
                    entry.get("true_product"),
                    entry.get("true_firmware_version"),
                    accepted_cpes_json,
                    entry.get("rubric_version"),
                    entry.get("label_status"),
                    entry.get("notes"),
                    ts,
                    device_id,
                ),
            )
            print(f"  UPDATE  {device_code} (mac={mac})")
        else:
            con.execute(
                """
                INSERT INTO ground_truth (
                    device_id, true_vendor, true_product, true_firmware_version,
                    accepted_cpes_json, rubric_version, label_status, notes,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    entry.get("true_vendor"),
                    entry.get("true_product"),
                    entry.get("true_firmware_version"),
                    accepted_cpes_json,
                    entry.get("rubric_version"),
                    entry.get("label_status"),
                    entry.get("notes"),
                    ts,
                    ts,
                ),
            )
            print(f"  INSERT  {device_code} (mac={mac})")

    con.commit()
    con.close()
    print("\nDone.")


if __name__ == "__main__":
    main()

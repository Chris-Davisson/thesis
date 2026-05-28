#!/usr/bin/env python3
"""
Load ground truth entries into the devices collection.

Reads from truth.toml if present; otherwise falls back to the [[truth]]
entries in config.toml. Resolves the target device by MAC address and writes
ground_truth as an embedded sub-document on the device. Safe to re-run —
upserts the sub-doc.

Usage:
    python truth.py
"""

import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from db import ensure_db, get_db, load_config


TRUTH_PATH = Path(__file__).parent / "truth.toml"


def load_truth_entries():
    """Return (entries, source_label). Prefer truth.toml, fall back to config.toml."""
    if TRUTH_PATH.exists():
        with open(TRUTH_PATH, "rb") as f:
            data = tomllib.load(f)
        return data.get("truth", []), TRUTH_PATH.name

    return load_config().get("truth", []), "config.toml"


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    ensure_db()
    entries, source = load_truth_entries()

    # TOML [[truth]] → list; [truth] → single dict. Normalize to list.
    if isinstance(entries, dict):
        entries = [entries]

    if not entries:
        print(f"No truth entries found in {source}")
        sys.exit(0)

    print(f"Loading {len(entries)} truth entry(ies) from {source}\n")

    db = get_db()

    for entry in entries:
        mac = (entry.get("mac") or "").strip()
        ip  = (entry.get("ip")  or "").strip()

        if not mac:
            print(f"  SKIP  missing mac — {entry}")
            continue

        device = db.devices.find_one({"mac": mac}, {"_id": 1, "device_code": 1, "ground_truth": 1})
        if device is None:
            print(f"  SKIP  no device found with mac={mac} (ip={ip}) — run ingest.py first")
            continue

        gt_doc = {
            "true_vendor":           entry.get("true_vendor"),
            "true_product":          entry.get("true_product"),
            "true_firmware_version": entry.get("true_firmware_version"),
            "accepted_cpes":         entry.get("accepted_cpes", []),
            "rubric_version":        entry.get("rubric_version"),
            "label_status":          entry.get("label_status"),
            "notes":                 entry.get("notes"),
            "updated_at":            now(),
        }

        if device.get("ground_truth") is None:
            gt_doc["created_at"] = now()
            action = "INSERT"
        else:
            gt_doc["created_at"] = device["ground_truth"].get("created_at") or now()
            action = "UPDATE"

        db.devices.update_one({"_id": device["_id"]}, {"$set": {"ground_truth": gt_doc}})
        print(f"  {action}  {device['device_code']} (mac={mac})")

    print("\nDone.")


if __name__ == "__main__":
    main()

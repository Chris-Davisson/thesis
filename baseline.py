#!/usr/bin/env python3
"""
Synthesize nmap-baseline model_runs.

For each scan, extracts the CPEs nmap itself emitted from the raw XML
(service-level + OS-level), normalizes them to CPE 2.3 long form, and writes
a model_runs doc with model.name='nmap'. The scorer then scores it like any
other model.

Usage:
    python baseline.py <scan_id>              # one baseline run
    python baseline.py --all                  # baseline every scan that doesn't have one
    python baseline.py --rebuild <scan_id>    # delete existing nmap baseline and redo
"""

import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from db import ensure_db, get_db, next_id


BASELINE_MODEL_NAME = "nmap"


# ---------------------------------------------------------------------------
# CPE extraction + normalization
# ---------------------------------------------------------------------------

def normalize_to_cpe23(cpe):
    """Convert nmap short-form CPE to 2.3 long form; return None if not a CPE."""
    if not isinstance(cpe, str):
        return None
    cpe = cpe.strip()

    # Already 2.3 long form
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) == 13:
            return cpe
        if len(parts) >= 5 and len(parts) < 13:
            parts += ["*"] * (13 - len(parts))
            return ":".join(parts)
        return None

    # Short form: cpe:/<part>:<vendor>:<product>[...]
    if cpe.startswith("cpe:/"):
        body = cpe[5:]
        fields = body.split(":")
        if len(fields) < 3:
            return None
        while len(fields) < 11:
            fields.append("*")
        fields = [f if f else "*" for f in fields]
        return "cpe:2.3:" + ":".join(fields)

    return None


def extract_nmap_cpes(xml_string):
    """Parse raw nmap XML and return a list of CPE strings (normalized to 2.3)."""
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return []

    cpes = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                if service is not None:
                    for cpe_elem in service.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text.strip())

        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                for osclass in osmatch.findall("osclass"):
                    attr_cpe = osclass.get("cpe")
                    if attr_cpe:
                        cpes.append(attr_cpe.strip())
                    for cpe_elem in osclass.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text.strip())

    seen = set()
    normalized = []
    for raw in cpes:
        n = normalize_to_cpe23(raw)
        if n and n not in seen:
            seen.add(n)
            normalized.append(n)

    return normalized


# ---------------------------------------------------------------------------
# Baseline writer
# ---------------------------------------------------------------------------

def build_baseline(db, scan_id, rebuild=False):
    """Create (or rebuild) a synthetic nmap-baseline model_run for a scan.

    Returns the new model_run_id, or -1 on skip.
    """
    scan = db.scans.find_one({"_id": scan_id}, {"nmap": 1})
    if scan is None:
        print(f"  SKIP  scan id={scan_id} not found")
        return -1

    existing = db.model_runs.find_one(
        {"scan_id": scan_id, "model.name": BASELINE_MODEL_NAME},
        {"_id": 1},
    )

    if existing and not rebuild:
        print(f"  SKIP  scan_id={scan_id} already has baseline (run id={existing['_id']}). Use --rebuild to redo.")
        return -1

    if rebuild and existing:
        db.model_runs.delete_one({"_id": existing["_id"]})
        print(f"  PURGE scan_id={scan_id} — deleted existing baseline run id={existing['_id']}")

    xml_string   = scan.get("nmap", {}).get("xml") or ""
    nmap_version = scan.get("nmap", {}).get("nmap_version") or ""

    all_cpes = extract_nmap_cpes(xml_string) if xml_string else []
    parsed_output = {"cpes": all_cpes}

    ts = datetime.now(timezone.utc).isoformat()
    run_id = next_id(db, "model_runs")

    trial_number = db.model_runs.count_documents({
        "scan_id":    scan_id,
        "model.name": BASELINE_MODEL_NAME,
    }) + 1

    db.model_runs.insert_one({
        "_id":           run_id,
        "scan_id":       scan_id,
        "prompt_id":     None,
        "trial_number":  trial_number,
        "doubled":       False,
        "model": {
            "name":        BASELINE_MODEL_NAME,
            "version":     nmap_version,
            "temperature": None,
            "top_p":       None,
            "max_tokens":  None,
            "seed":        None,
        },
        "messages":      None,
        "raw_output":    None,
        "parsed_output": parsed_output,
        "started_at":    ts,
        "ended_at":      ts,
        "status":        "complete",
        "error":         None,
        "scores":        [],
    })

    print(f"  BASELINE scan_id={scan_id} -> run id={run_id} ({len(all_cpes)} CPE(s))")
    return run_id


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Synthesize nmap-baseline model_runs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("scan_id", nargs="?", type=int, help="Build baseline for one scan")
    group.add_argument("--all", action="store_true", help="Build baseline for every scan without one")
    group.add_argument("--rebuild", type=int, help="Delete existing baseline for a scan and redo")
    args = parser.parse_args()

    ensure_db()
    db = get_db()

    if args.all:
        # Scans without an 'nmap' baseline
        have_baseline = set(
            doc["scan_id"] for doc in db.model_runs.find(
                {"model.name": BASELINE_MODEL_NAME}, {"scan_id": 1}
            )
        )
        scans_needing = [
            doc["_id"] for doc in db.scans.find({}, {"_id": 1}).sort("_id")
            if doc["_id"] not in have_baseline
        ]
        if not scans_needing:
            print("No scans need a baseline.")
            return
        print(f"Building baselines for {len(scans_needing)} scan(s)...")
        for sid in scans_needing:
            build_baseline(db, sid)
    elif args.rebuild is not None:
        build_baseline(db, args.rebuild, rebuild=True)
    else:
        build_baseline(db, args.scan_id)

    print("\nDone.")


if __name__ == "__main__":
    main()

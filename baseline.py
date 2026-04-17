#!/usr/bin/env python3
"""
Synthesize nmap-baseline model_runs.

For each aggregated_input, extracts the CPEs nmap itself emitted from the
underlying scan XML (service-level + OS-level), normalizes them to CPE 2.3
long form, and writes a model_runs row with model_name='nmap'. The existing
scorer then scores it like any other model.

Usage:
    python baseline.py <aggregated_input_id>      # one baseline run
    python baseline.py --all                       # baseline for every agg_input that doesn't have one
    python baseline.py --rebuild <agg_id>          # delete existing nmap baseline and redo
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from db import ensure_db, get_connection


BASELINE_MODEL_NAME = "nmap"


# ---------------------------------------------------------------------------
# CPE extraction + normalization
# ---------------------------------------------------------------------------

def normalize_to_cpe23(cpe):
    """Convert nmap's short-form CPE (cpe:/h:vendor:product) to 2.3 long form.

    Short form:  cpe:/<part>:<vendor>:<product>[:<version>[:<update>[:<edition>[:<lang>]]]]
    Long form:   cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

    Returns None if the input doesn't look like a CPE.
    """
    if not isinstance(cpe, str):
        return None
    cpe = cpe.strip()

    # Already 2.3 long form
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) == 13:
            return cpe
        # Pad short 2.3 form with wildcards
        if len(parts) >= 5 and len(parts) < 13:
            parts += ["*"] * (13 - len(parts))
            return ":".join(parts)
        return None

    # Short form: cpe:/<part>:<vendor>:<product>[...]
    if cpe.startswith("cpe:/"):
        body = cpe[5:]  # strip "cpe:/"
        fields = body.split(":")
        if len(fields) < 3:
            return None  # need at least part:vendor:product
        # Pad to 11 data fields (part + 10 more)
        while len(fields) < 11:
            fields.append("*")
        # Replace empty strings with wildcards
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
        # Skip hosts that aren't up
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Service-level CPEs — from <port><service><cpe>
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

        # OS-level CPEs — from <os><osmatch><osclass cpe="..."> and
        # <os><osmatch><osclass><cpe>...</cpe></osclass>
        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                for osclass in osmatch.findall("osclass"):
                    # Attribute form
                    attr_cpe = osclass.get("cpe")
                    if attr_cpe:
                        cpes.append(attr_cpe.strip())
                    # Child element form
                    for cpe_elem in osclass.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text.strip())

    # Normalize, drop Nones, dedupe while preserving order
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

def build_baseline(con, agg_input_id, rebuild=False):
    """Create (or rebuild) a synthetic nmap-baseline model_run for an aggregated_input.

    Returns the new model_run_id, or -1 on skip.
    """
    agg = con.execute(
        "SELECT id, scan_session_id FROM aggregated_inputs WHERE id = ?",
        (agg_input_id,),
    ).fetchone()
    if agg is None:
        print(f"  SKIP  aggregated_input id={agg_input_id} not found")
        return -1

    # Check for existing baseline
    existing = con.execute(
        """
        SELECT id FROM model_runs
        WHERE aggregated_input_id = ? AND model_name = ?
        """,
        (agg_input_id, BASELINE_MODEL_NAME),
    ).fetchone()

    if existing and not rebuild:
        print(f"  SKIP  agg_input_id={agg_input_id} already has baseline (model_run id={existing['id']}). Use --rebuild to redo.")
        return -1

    if rebuild and existing:
        # Delete any scores first (scores.model_run_id is NOT NULL FK)
        con.execute("DELETE FROM scores WHERE model_run_id = ?", (existing["id"],))
        con.execute("DELETE FROM model_runs WHERE id = ?", (existing["id"],))
        print(f"  PURGE agg_input_id={agg_input_id} — deleted existing baseline model_run id={existing['id']}")

    # Pull the scan_run XML. One aggregated_input = one scan_session = one scan_run
    # in the current pipeline. If multiple scan_runs exist for a session, merge CPEs.
    scan_runs = con.execute(
        "SELECT id, stdout_text, tool_version FROM scan_runs WHERE scan_session_id = ?",
        (agg["scan_session_id"],),
    ).fetchall()

    if not scan_runs:
        print(f"  SKIP  agg_input_id={agg_input_id} — no scan_runs for session_id={agg['scan_session_id']}")
        return -1

    all_cpes = []
    seen = set()
    nmap_version = None
    for sr in scan_runs:
        if not sr["stdout_text"]:
            continue
        if nmap_version is None:
            nmap_version = sr["tool_version"]
        for cpe in extract_nmap_cpes(sr["stdout_text"]):
            if cpe not in seen:
                seen.add(cpe)
                all_cpes.append(cpe)

    parsed_output = {"cpes": all_cpes} if all_cpes else {"cpes": []}

    ts = datetime.now(timezone.utc).isoformat()
    cur = con.execute(
        """
        INSERT INTO model_runs (
            aggregated_input_id, experiment_id, prompt_id, trial_number,
            model_name, model_version, temperature, top_p, max_tokens, seed,
            conversation_history_json, raw_output_text, parsed_output_json,
            started_at, ended_at, status, error_text
        ) VALUES (?, NULL, NULL, 1, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, 'complete', NULL)
        """,
        (
            agg_input_id,
            BASELINE_MODEL_NAME,
            nmap_version or "",
            json.dumps(parsed_output),
            ts,
            ts,
        ),
    )
    run_id = cur.lastrowid

    print(f"  BASELINE agg_input_id={agg_input_id} -> model_run id={run_id} ({len(all_cpes)} CPE(s))")
    return run_id


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Synthesize nmap-baseline model_runs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("aggregated_input_id", nargs="?", type=int, help="Build baseline for one aggregated_input")
    group.add_argument("--all", action="store_true", help="Build baseline for every aggregated_input without one")
    group.add_argument("--rebuild", type=int, help="Delete existing baseline for an aggregated_input and redo")
    args = parser.parse_args()

    ensure_db()
    con = get_connection()

    if args.all:
        rows = con.execute(
            """
            SELECT ai.id FROM aggregated_inputs ai
            WHERE NOT EXISTS (
                SELECT 1 FROM model_runs mr
                WHERE mr.aggregated_input_id = ai.id AND mr.model_name = ?
            )
            ORDER BY ai.id
            """,
            (BASELINE_MODEL_NAME,),
        ).fetchall()
        if not rows:
            print("No aggregated_inputs need a baseline.")
            con.close()
            return
        print(f"Building baselines for {len(rows)} aggregated_input(s)...")
        for row in rows:
            build_baseline(con, row["id"])
    elif args.rebuild is not None:
        build_baseline(con, args.rebuild, rebuild=True)
    else:
        build_baseline(con, args.aggregated_input_id)

    con.commit()
    con.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
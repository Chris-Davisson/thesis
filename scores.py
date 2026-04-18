#!/usr/bin/env python3
"""
Score model_run outputs against ground truth.

For each predicted CPE in a model_run, finds the best matching accepted CPE
from ground truth and writes one scores row. "Best" = highest tier (exact >
partial > related), tiebroken by number of field matches.

Usage:
    python scores.py <model_run_id>        # score one run
    python scores.py --all                  # score all unscored runs
    python scores.py --rescore <run_id>     # delete existing scores and redo
"""

import argparse
import json
import sys

from db import ensure_db, get_connection


SCORER_VERSION = "1.0"

TIER_VALUES = {
    "exact":   1.0,
    "partial": 0.5,
    "related": 0.25,
    "none":    0.0,
}

TIER_RANK = {"exact": 3, "partial": 2, "related": 1, "none": 0}


def parse_cpe(cpe_str):
    """Split a CPE 2.3 string into its 11 meaningful fields plus the two prefix tokens.

    Returns a dict with keys: part, vendor, product, version, update, edition,
    language, sw_edition, target_sw, target_hw, other. Returns None if malformed.
    """
    if not isinstance(cpe_str, str):
        return None
    parts = cpe_str.split(":")
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {
        "part":       parts[2],
        "vendor":     parts[3],
        "product":    parts[4],
        "version":    parts[5],
        "update":     parts[6],
        "edition":    parts[7],
        "language":   parts[8],
        "sw_edition": parts[9],
        "target_sw":  parts[10],
        "target_hw":  parts[11],
        "other":      parts[12],
    }


def normalize_accepted_cpes(accepted_cpes_json):
    """Accept both flat-list and tiered-dict format. Return list of {cpe, tier} dicts."""
    if not accepted_cpes_json:
        return []
    try:
        data = json.loads(accepted_cpes_json)
    except json.JSONDecodeError:
        return []

    normalized = []
    for entry in data:
        if isinstance(entry, str):
            # Legacy flat format — treat as exact
            normalized.append({"cpe": entry, "tier": "exact"})
        elif isinstance(entry, dict) and "cpe" in entry:
            normalized.append({
                "cpe":  entry["cpe"],
                "tier": entry.get("tier", "exact"),
            })
    return normalized


def compare_cpes(predicted, accepted):
    """Compare a predicted CPE dict to an accepted CPE dict.

    Returns (part_ok, vendor_ok, product_ok, version_ok, field_match_count).
    Version is correct if it matches OR if the accepted version is a wildcard.
    """
    part_ok    = predicted["part"]    == accepted["part"]
    vendor_ok  = predicted["vendor"]  == accepted["vendor"]
    product_ok = predicted["product"] == accepted["product"]
    version_ok = (predicted["version"] == accepted["version"]
                  or accepted["version"] == "*")

    count = sum([part_ok, vendor_ok, product_ok, version_ok])
    return part_ok, vendor_ok, product_ok, version_ok, count


def score_prediction(predicted_cpe_str, accepted_entries):
    """Find the best-matching accepted CPE for a single prediction.

    Returns a dict with all the fields needed for a scores row.
    """
    predicted = parse_cpe(predicted_cpe_str)
    if predicted is None:
        return {
            "predicted_cpe":        predicted_cpe_str,
            "matched_accepted_cpe": None,
            "part_correct":         0,
            "vendor_correct":       0,
            "product_correct":      0,
            "version_correct":      0,
            "exact_match":          0,
            "cve_lookup_valid":     0,
            "best_match_tier":      "none",
            "match_score":          0.0,
            "predicted_vendor":     None,
            "predicted_product":    None,
            "score_notes":          "malformed CPE string",
        }

    best = None
    best_sort_key = (-1, -1)  # (tier_rank, field_match_count)

    for entry in accepted_entries:
        accepted = parse_cpe(entry["cpe"])
        if accepted is None:
            continue
        part_ok, vendor_ok, product_ok, version_ok, count = compare_cpes(predicted, accepted)

        # Require part+vendor+product to match before considering this a real match
        if not (part_ok and vendor_ok and product_ok):
            continue

        tier = entry["tier"]
        sort_key = (TIER_RANK.get(tier, 0), count)
        if sort_key > best_sort_key:
            best_sort_key = sort_key
            best = {
                "accepted":   entry,
                "part_ok":    part_ok,
                "vendor_ok":  vendor_ok,
                "product_ok": product_ok,
                "version_ok": version_ok,
            }

    if best is None:
        return {
            "predicted_cpe":        predicted_cpe_str,
            "matched_accepted_cpe": None,
            "part_correct":         0,
            "vendor_correct":       0,
            "product_correct":      0,
            "version_correct":      0,
            "exact_match":          0,
            "cve_lookup_valid":     0,
            "best_match_tier":      "none",
            "match_score":          0.0,
            "predicted_vendor":     predicted["vendor"],
            "predicted_product":    predicted["product"],
            "score_notes":          None,
        }

    part_ok    = best["part_ok"]
    vendor_ok  = best["vendor_ok"]
    product_ok = best["product_ok"]
    version_ok = best["version_ok"]
    tier       = best["accepted"]["tier"]

    return {
        "predicted_cpe":        predicted_cpe_str,
        "matched_accepted_cpe": best["accepted"]["cpe"],
        "part_correct":         int(part_ok),
        "vendor_correct":       int(vendor_ok),
        "product_correct":      int(product_ok),
        "version_correct":      int(version_ok),
        "exact_match":          int(part_ok and vendor_ok and product_ok and version_ok),
        "cve_lookup_valid":     int(part_ok and vendor_ok and product_ok),
        "best_match_tier":      tier,
        "match_score":          TIER_VALUES.get(tier, 0.0),
        "predicted_vendor":     predicted["vendor"],
        "predicted_product":    predicted["product"],
        "score_notes":          None,
    }


def get_predicted_cpes(parsed_output_json):
    """Extract the list of CPE strings from a model_run's parsed_output_json."""
    if not parsed_output_json:
        return []
    try:
        data = json.loads(parsed_output_json)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        if "cpes" in data and isinstance(data["cpes"], list):
            return data["cpes"]
        if "cpe" in data and isinstance(data["cpe"], str):
            return [data["cpe"]]
    return []


def score_model_run(con, model_run_id, rescore=False):
    """Score a single model_run. Returns number of scores rows written, or -1 on skip."""
    run = con.execute(
        """
        SELECT mr.id, mr.parsed_output_json, ss.device_id
        FROM model_runs mr
        JOIN aggregated_inputs ai ON ai.id = mr.aggregated_input_id
        JOIN scan_sessions ss     ON ss.id = ai.scan_session_id
        WHERE mr.id = ?
        """,
        (model_run_id,),
    ).fetchone()

    if run is None:
        print(f"  SKIP  model_run id={model_run_id} not found")
        return -1

    gt = con.execute(
        "SELECT id, accepted_cpes_json FROM ground_truth WHERE device_id = ?",
        (run["device_id"],),
    ).fetchone()

    if gt is None:
        print(f"  SKIP  model_run id={model_run_id} — no ground_truth for device_id={run['device_id']}")
        return -1

    existing = con.execute(
        "SELECT COUNT(*) AS n FROM scores WHERE model_run_id = ?", (model_run_id,)
    ).fetchone()["n"]

    if existing and not rescore:
        print(f"  SKIP  model_run id={model_run_id} already scored ({existing} rows). Use --rescore to redo.")
        return -1

    if rescore and existing:
        con.execute("DELETE FROM scores WHERE model_run_id = ?", (model_run_id,))
        print(f"  PURGE model_run id={model_run_id} — deleted {existing} existing scores rows")

    predicted_cpes = get_predicted_cpes(run["parsed_output_json"])
    accepted       = normalize_accepted_cpes(gt["accepted_cpes_json"])

    if not predicted_cpes:
        # Write a single null row so we can distinguish "scored but no output" from "not scored"
        con.execute(
            """
            INSERT INTO scores (
                model_run_id, ground_truth_id, predicted_cpe, matched_accepted_cpe,
                part_correct, vendor_correct, product_correct, version_correct,
                exact_match, cve_lookup_valid, best_match_tier, match_score,
                predicted_vendor, predicted_product, score_notes, scorer_version
            ) VALUES (?, ?, NULL, NULL, 0, 0, 0, 0, 0, 0, 'none', 0.0, NULL, NULL, ?, ?)
            """,
            (model_run_id, gt["id"], "no predicted CPEs", SCORER_VERSION),
        )
        print(f"  SCORE model_run id={model_run_id} — no predictions (1 null row)")
        return 1

    written = 0
    for cpe_str in predicted_cpes:
        result = score_prediction(cpe_str, accepted)
        con.execute(
            """
            INSERT INTO scores (
                model_run_id, ground_truth_id, predicted_cpe, matched_accepted_cpe,
                part_correct, vendor_correct, product_correct, version_correct,
                exact_match, cve_lookup_valid, best_match_tier, match_score,
                predicted_vendor, predicted_product, score_notes, scorer_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_run_id, gt["id"],
                result["predicted_cpe"], result["matched_accepted_cpe"],
                result["part_correct"], result["vendor_correct"],
                result["product_correct"], result["version_correct"],
                result["exact_match"], result["cve_lookup_valid"],
                result["best_match_tier"], result["match_score"],
                result["predicted_vendor"], result["predicted_product"],
                result["score_notes"], SCORER_VERSION,
            ),
        )
        written += 1

    print(f"  SCORE model_run id={model_run_id} — {written} prediction(s) scored")
    return written


def main():
    parser = argparse.ArgumentParser(description="Score model_run outputs against ground truth")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("model_run_id", nargs="?", type=int, help="Score one model_run")
    group.add_argument("--all", action="store_true", help="Score all unscored model_runs")
    group.add_argument("--rescore", type=int, help="Delete existing scores for a model_run and redo")
    args = parser.parse_args()

    ensure_db()
    con = get_connection()

    if args.all:
        rows = con.execute(
            """
            SELECT mr.id FROM model_runs mr
            LEFT JOIN scores s ON s.model_run_id = mr.id
            WHERE s.id IS NULL AND mr.status = 'complete'
            ORDER BY mr.id
            """
        ).fetchall()
        if not rows:
            print("No unscored model_runs.")
            con.close()
            return
        print(f"Scoring {len(rows)} model_run(s)...")
        for row in rows:
            score_model_run(con, row["id"])
    elif args.rescore is not None:
        score_model_run(con, args.rescore, rescore=True)
    else:
        score_model_run(con, args.model_run_id)

    try:
        con.commit()
    except Exception as e:
        print(f"Commit failed error: {e}")
    con.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
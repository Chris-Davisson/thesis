#!/usr/bin/env python3
"""
Score model_run outputs against ground truth.

For each predicted CPE in a model_run, finds the best matching accepted CPE
from the device's embedded ground_truth and writes an entry into the run's
`scores` array. "Best" = highest tier (exact > partial > related), tiebroken
by number of field matches.

Usage:
    python scores.py <model_run_id>        # score one run
    python scores.py --all                  # score all unscored complete runs
    python scores.py --rescore <run_id>     # clear existing scores and redo
"""

import argparse
from datetime import datetime, timezone

from db import ensure_db, get_db


SCORER_VERSION = "1.0"

TIER_VALUES = {"exact": 1.0, "partial": 0.5, "related": 0.25, "none": 0.0}
TIER_RANK   = {"exact": 3,   "partial": 2,   "related": 1,   "none": 0}


def now():
    return datetime.now(timezone.utc).isoformat()


def parse_cpe(cpe_str):
    """Split a CPE 2.3 string into its 11 meaningful fields. Returns None if malformed."""
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


def normalize_accepted_cpes(accepted_cpes):
    """Accept either flat-list or tiered-dict format. Returns list of {cpe, tier}."""
    if not accepted_cpes:
        return []
    normalized = []
    for entry in accepted_cpes:
        if isinstance(entry, str):
            normalized.append({"cpe": entry, "tier": "exact"})
        elif isinstance(entry, dict) and "cpe" in entry:
            normalized.append({"cpe": entry["cpe"], "tier": entry.get("tier", "exact")})
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
    best_sort_key = (-1, -1)

    for entry in accepted_entries:
        accepted = parse_cpe(entry["cpe"])
        if accepted is None:
            continue
        part_ok, vendor_ok, product_ok, version_ok, count = compare_cpes(predicted, accepted)

        # Require part+vendor+product before considering it a real match
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


def get_predicted_cpes(parsed_output):
    """Extract the list of CPE strings from a model_run's parsed_output dict."""
    if not parsed_output or not isinstance(parsed_output, dict):
        return []
    if "cpes" in parsed_output and isinstance(parsed_output["cpes"], list):
        return parsed_output["cpes"]
    if "cpe" in parsed_output and isinstance(parsed_output["cpe"], str):
        return [parsed_output["cpe"]]
    return []


def score_model_run(db, model_run_id, rescore=False):
    """Score a single model_run. Returns number of score entries written, or -1 on skip."""
    run = db.model_runs.find_one(
        {"_id": model_run_id},
        {"scan_id": 1, "parsed_output": 1, "scores": 1},
    )
    if run is None:
        print(f"  SKIP  run id={model_run_id} not found")
        return -1

    scan = db.scans.find_one({"_id": run["scan_id"]}, {"device_id": 1})
    if scan is None:
        print(f"  SKIP  run id={model_run_id} — scan_id={run['scan_id']} missing")
        return -1

    device = db.devices.find_one(
        {"_id": scan["device_id"]},
        {"ground_truth": 1, "device_code": 1},
    )
    if device is None or not device.get("ground_truth"):
        print(f"  SKIP  run id={model_run_id} — no ground_truth for device_id={scan['device_id']}")
        return -1

    existing_count = len(run.get("scores") or [])
    if existing_count and not rescore:
        print(f"  SKIP  run id={model_run_id} already scored ({existing_count} entries). Use --rescore to redo.")
        return -1

    if rescore and existing_count:
        print(f"  PURGE run id={model_run_id} — clearing {existing_count} existing score entries")

    predicted_cpes = get_predicted_cpes(run.get("parsed_output"))
    accepted       = normalize_accepted_cpes(device["ground_truth"].get("accepted_cpes"))

    ts = now()
    score_entries = []

    if not predicted_cpes:
        # Single null row so "scored but empty" is distinguishable from "not scored"
        score_entries.append({
            "predicted_cpe":        None,
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
            "score_notes":          "no predicted CPEs",
            "scorer_version":       SCORER_VERSION,
            "created_at":           ts,
        })
    else:
        for cpe_str in predicted_cpes:
            result = score_prediction(cpe_str, accepted)
            result["scorer_version"] = SCORER_VERSION
            result["created_at"]     = ts
            score_entries.append(result)

    db.model_runs.update_one(
        {"_id": model_run_id},
        {"$set": {"scores": score_entries}},
    )

    n = len(score_entries)
    if predicted_cpes:
        print(f"  SCORE run id={model_run_id} — {n} prediction(s) scored")
    else:
        print(f"  SCORE run id={model_run_id} — no predictions (1 null entry)")
    return n


def main():
    parser = argparse.ArgumentParser(description="Score model_run outputs against ground truth")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("model_run_id", nargs="?", type=int, help="Score one model_run")
    group.add_argument("--all", action="store_true", help="Score all unscored model_runs")
    group.add_argument("--rescore", type=int, help="Clear existing scores for a model_run and redo")
    args = parser.parse_args()

    ensure_db()
    db = get_db()

    if args.all:
        rows = list(db.model_runs.find(
            {"status": "complete", "$or": [{"scores": {"$exists": False}}, {"scores": {"$size": 0}}]},
            {"_id": 1},
        ).sort("_id"))
        if not rows:
            print("No unscored model_runs.")
            return
        print(f"Scoring {len(rows)} model_run(s)...")
        for row in rows:
            score_model_run(db, row["_id"])
    elif args.rescore is not None:
        score_model_run(db, args.rescore, rescore=True)
    else:
        score_model_run(db, args.model_run_id)

    print("\nDone.")


if __name__ == "__main__":
    main()

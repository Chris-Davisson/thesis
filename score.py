#!/usr/bin/env python3
"""
Score all completed model_runs by comparing predicted CPEs against ground truth.

Writes a `scores` array into each model_run document. Safe to re-run
(replaces any existing scores on every processed run).

Usage:
    python score.py                    # score everything
    python score.py --workers 16       # control parallelism
    python score.py --batch 500        # bulk-write batch size
    python score.py --scan-id 5        # only runs for scan #5
    python score.py --run-id 42        # single run
    python score.py --unscored-only    # skip runs that already have scores
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from pymongo import UpdateOne

from db import ensure_db, get_db

# ── Tier weights ───────────────────────────────────────────────────────────────

TIER_WEIGHTS: dict[str, float] = {
    "exact":   1.00,
    "partial": 0.50,
    "related": 0.25,
    "none":    0.00,
}

# CPE 2.3 has 13 colon-separated fields:
# cpe : 2.3 : <part> : <vendor> : <product> : <version> : <update> :
# <edition> : <language> : <sw_edition> : <target_sw> : <target_hw> : <other>
_CPE_LEN = 13
_IDX_PART    = 2
_IDX_VENDOR  = 3
_IDX_PRODUCT = 4
_IDX_VERSION = 5


# ── CPE helpers ────────────────────────────────────────────────────────────────

def _parse(cpe: str) -> list[str]:
    """Split CPE 2.3 string into 13 lowercase fields; pad short strings with *."""
    parts = cpe.lower().split(":")
    if len(parts) < _CPE_LEN:
        parts += ["*"] * (_CPE_LEN - len(parts))
    return parts[:_CPE_LEN]


def _cpe_accepted_by(predicted: str, truth_cpe: str) -> bool:
    """
    True when every non-wildcard field in truth_cpe equals the corresponding
    field in predicted.  Truth wildcards ('*') accept any predicted value.
    The '-' (not-applicable) marker must match exactly.
    """
    p = _parse(predicted)
    t = _parse(truth_cpe)
    for i in range(_IDX_PART, _CPE_LEN):
        tv = t[i]
        if tv == "*":
            continue        # truth wildcard accepts anything
        if tv != p[i]:
            return False
    return True


def _field_overlap(p: list[str], t: list[str]) -> int:
    """Count matching non-wildcard fields at positions part/vendor/product/version."""
    return sum(
        1
        for i in (_IDX_PART, _IDX_VENDOR, _IDX_PRODUCT, _IDX_VERSION)
        if p[i] != "*" and t[i] != "*" and p[i] == t[i]
    )


def _find_best(predicted_cpe: str, accepted_cpes: list[dict]) -> tuple[str, list[str]]:
    """
    Return (best_tier, truth_fields_for_metrics).

    Pass 1: find the accepted CPE with the highest tier weight that the
            predicted CPE satisfies.
    Pass 2: if nothing matched, find the closest truth CPE by field overlap
            (used only for per-field diagnostic metrics, tier stays "none").
    """
    best_tier   = "none"
    best_weight = -1.0
    best_truth: list[str] | None = None

    for entry in accepted_cpes:
        if _cpe_accepted_by(predicted_cpe, entry["cpe"]):
            w = TIER_WEIGHTS.get(entry.get("tier", "none"), 0.0)
            if w > best_weight:
                best_weight = w
                best_tier   = entry["tier"]
                best_truth  = _parse(entry["cpe"])

    if best_truth is None and accepted_cpes:
        p = _parse(predicted_cpe)
        best_overlap = -1
        for entry in accepted_cpes:
            t = _parse(entry["cpe"])
            ov = _field_overlap(p, t)
            if ov > best_overlap:
                best_overlap = ov
                best_truth   = t

    return best_tier, (best_truth or ["*"] * _CPE_LEN)


# ── Per-CPE scoring ────────────────────────────────────────────────────────────

def _score_one_cpe(predicted_cpe: str, accepted_cpes: list[dict]) -> dict:
    """Return a score sub-document for a single predicted CPE."""
    p = _parse(predicted_cpe)
    tier, truth = _find_best(predicted_cpe, accepted_cpes)

    def _correct(pi: int) -> int:
        return int(
            p[pi] == truth[pi]
            and p[pi] not in ("*", "-")
            and truth[pi] not in ("*", "-")
        )

    return {
        "predicted_cpe":    predicted_cpe,
        "best_match_tier":  tier,
        "match_score":      TIER_WEIGHTS[tier] if tier in TIER_WEIGHTS else 0.0,
        "exact_match":      int(tier == "exact"),
        "part_correct":     _correct(_IDX_PART),
        "vendor_correct":   _correct(_IDX_VENDOR),
        "product_correct":  _correct(_IDX_PRODUCT),
        "version_correct":  _correct(_IDX_VERSION),
        "cve_lookup_valid": 0,
    }


# ── Run-level worker (called in thread pool) ───────────────────────────────────

def _score_run(run: dict, truth_by_scan: dict[int, list[dict]]) -> tuple[int, list[dict]]:
    """
    Compute scores for one model_run.
    Returns (run_id, scores_list) — pure computation, no DB access.
    """
    scan_id       = run.get("scan_id")
    accepted_cpes = truth_by_scan.get(scan_id, [])

    parsed = run.get("parsed_output") or {}
    if isinstance(parsed, dict):
        cpes: list[str] = parsed.get("cpes") or []
        if not cpes and "cpe" in parsed:
            val = parsed["cpe"]
            if isinstance(val, str):
                cpes = [val]
    else:
        cpes = []

    scores = [
        _score_one_cpe(cpe, accepted_cpes)
        for cpe in cpes
        if isinstance(cpe, str) and cpe.startswith("cpe:")
    ]
    return run["_id"], scores


# ── Reference-data loader ──────────────────────────────────────────────────────

def _build_truth_by_scan(db) -> dict[int, list[dict]]:
    """Return {scan_id: accepted_cpes_list} for every scan in the DB."""
    devices = {
        d["_id"]: (d.get("ground_truth") or {}).get("accepted_cpes", [])
        for d in db.devices.find({}, {"ground_truth.accepted_cpes": 1})
    }
    return {
        scan["_id"]: devices.get(scan.get("device_id"), [])
        for scan in db.scans.find({}, {"_id": 1, "device_id": 1})
    }


# ── Bulk-write helper ──────────────────────────────────────────────────────────

def _flush(db, ops: list) -> None:
    if ops:
        db.model_runs.bulk_write(ops, ordered=False)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score model_run CPE predictions against ground truth"
    )
    parser.add_argument("--workers",       type=int, default=8,
                        help="Thread-pool size (default: 8)")
    parser.add_argument("--batch",         type=int, default=200,
                        help="MongoDB bulk-write batch size (default: 200)")
    parser.add_argument("--scan-id",       type=int, default=None,
                        help="Restrict to a single scan_id")
    parser.add_argument("--run-id",        type=int, default=None,
                        help="Score only one specific run_id")
    parser.add_argument("--unscored-only", action="store_true",
                        help="Skip runs that already have a non-empty scores array")
    args = parser.parse_args()

    ensure_db()
    db = get_db()

    # ── Load reference data once ───────────────────────────────────────────────
    print("Loading ground truth…")
    truth_by_scan = _build_truth_by_scan(db)
    covered = sum(1 for v in truth_by_scan.values() if v)
    print(f"  {len(truth_by_scan)} scan(s), {covered} with ground truth\n")

    # ── Build query ────────────────────────────────────────────────────────────
    query: dict = {"status": "complete"}
    if args.run_id is not None:
        query["_id"] = args.run_id
    elif args.scan_id is not None:
        query["scan_id"] = args.scan_id
    if args.unscored_only:
        query["$or"] = [{"scores": {"$exists": False}}, {"scores": []}]

    runs = list(db.model_runs.find(
        query, {"_id": 1, "scan_id": 1, "parsed_output": 1}
    ))

    if not runs:
        print("No runs match the query — nothing to score.")
        return

    total = len(runs)
    print(f"Scoring {total} run(s) with {args.workers} worker(s)…\n")

    # ── Parallel scoring ───────────────────────────────────────────────────────
    done = 0
    failed = 0
    pending: list[UpdateOne] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_score_run, run, truth_by_scan): run["_id"]
            for run in runs
        }

        for fut in as_completed(futures):
            try:
                run_id, scores = fut.result()
            except Exception as exc:
                run_id = futures[fut]
                print(f"\n  ERROR run_id={run_id}: {exc}")
                failed += 1
                done += 1
                continue

            pending.append(UpdateOne({"_id": run_id}, {"$set": {"scores": scores}}))
            done += 1

            # Flush batch
            if len(pending) >= args.batch:
                _flush(db, pending)
                pending.clear()

            # Progress line
            pct = done * 100 // total
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {done}/{total} ({pct}%) ", end="", flush=True)

    _flush(db, pending)

    print(f"\n\nDone.  {done - failed} scored, {failed} error(s).")


if __name__ == "__main__":
    main()

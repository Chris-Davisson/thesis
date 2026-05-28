#!/usr/bin/env python3
"""
Export scoring data to a single multi-sheet xlsx file.

Produces five sheets:
  - scores_wide       : one row per scored prediction (atomic facts)
  - summary_by_model  : metrics grouped by (device_code, model_name)
  - summary_by_prompt : metrics grouped by (model_name, prompt_name+version)
  - variance_by_config: metrics grouped by (scan_id, model_name, prompt_id, temperature)
  - run_manifest      : one row per model_run (sanity check artifact)

Usage:
    python export.py                      # exports to exports/<timestamp>.xlsx
    python export.py --out my_export.xlsx # export to a specific file
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("ERROR: pandas not installed. Run: pip install pandas openpyxl")
    sys.exit(1)

from db import ensure_db, get_db


EXPORTS_DIR = Path(__file__).parent / "exports"


# ---------------------------------------------------------------------------
# Build the wide scores DataFrame by reading each collection and joining in
# pandas. Collections are small (hundreds of rows at thesis scale).
# ---------------------------------------------------------------------------

def build_scores_wide(db) -> pd.DataFrame:
    runs = list(db.model_runs.find({}))
    if not runs:
        return pd.DataFrame()

    devices = {d["_id"]: d for d in db.devices.find({})}
    scans   = {s["_id"]: s for s in db.scans.find({})}
    prompts = {p["_id"]: p for p in db.prompts.find({})}

    rows = []
    for run in runs:
        scores = run.get("scores") or []
        if not scores:
            continue

        scan   = scans.get(run.get("scan_id"))   or {}
        device = devices.get(scan.get("device_id")) if scan else {}
        device = device or {}
        prompt = prompts.get(run.get("prompt_id")) if run.get("prompt_id") else {}
        prompt = prompt or {}
        nmap   = scan.get("nmap") or {}
        gt     = device.get("ground_truth") or {}
        model  = run.get("model") or {}

        for score in scores:
            rows.append({
                # Device context
                "device_id":             device.get("_id"),
                "device_code":           device.get("device_code"),
                "device_manufacturer":   device.get("manufacturer"),
                "device_model":          device.get("model"),
                "device_type":           device.get("device_type"),

                # Scan context (one doc now holds session + run + agg_input)
                "scan_id":               scan.get("_id"),
                "target_ip":             scan.get("target_ip"),
                "scan_hostname":         scan.get("hostname"),
                "scan_name":             nmap.get("scan_name"),
                "nmap_version":          nmap.get("nmap_version"),
                "parser_version":        scan.get("parser_version"),

                # Model run context
                "model_run_id":          run.get("_id"),
                "model_name":            model.get("name"),
                "model_version":         model.get("version"),
                "temperature":           model.get("temperature"),
                "top_p":                 model.get("top_p"),
                "max_tokens":            model.get("max_tokens"),
                "seed":                  model.get("seed"),
                "trial_number":          run.get("trial_number"),
                "doubled":               run.get("doubled"),
                "run_status":            run.get("status"),
                "run_started_at":        run.get("started_at"),
                "run_ended_at":          run.get("ended_at"),

                # Prompt context
                "prompt_id":             prompt.get("_id"),
                "prompt_name":           prompt.get("prompt_name"),
                "prompt_version":        prompt.get("prompt_version"),

                # Ground truth context
                "true_vendor":           gt.get("true_vendor"),
                "true_product":          gt.get("true_product"),
                "true_firmware_version": gt.get("true_firmware_version"),
                "rubric_version":        gt.get("rubric_version"),
                "label_status":          gt.get("label_status"),

                # The prediction
                "predicted_cpe":         score.get("predicted_cpe"),
                "predicted_vendor":      score.get("predicted_vendor"),
                "predicted_product":     score.get("predicted_product"),
                "matched_accepted_cpe":  score.get("matched_accepted_cpe"),

                # Field-level correctness
                "part_correct":          score.get("part_correct"),
                "vendor_correct":        score.get("vendor_correct"),
                "product_correct":       score.get("product_correct"),
                "version_correct":       score.get("version_correct"),

                # Aggregated correctness
                "exact_match":           score.get("exact_match"),
                "cve_lookup_valid":      score.get("cve_lookup_valid"),
                "best_match_tier":       score.get("best_match_tier"),
                "match_score":           score.get("match_score"),
                "score_notes":           score.get("score_notes"),
                "scorer_version":        score.get("scorer_version"),
                "scored_at":             score.get("created_at"),
            })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["device_code", "model_name", "model_run_id"]).reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# One row per model_run — shows error/empty runs that scores_wide can't
# ---------------------------------------------------------------------------

def build_run_manifest(db) -> pd.DataFrame:
    runs = list(db.model_runs.find({}))
    if not runs:
        return pd.DataFrame()

    devices = {d["_id"]: d for d in db.devices.find({}, {"device_code": 1})}
    scans   = {s["_id"]: s for s in db.scans.find({}, {"device_id": 1})}
    prompts = {p["_id"]: p for p in db.prompts.find({}, {"prompt_name": 1, "prompt_version": 1})}

    rows = []
    for run in runs:
        scan   = scans.get(run.get("scan_id"))   or {}
        device = devices.get(scan.get("device_id")) if scan else {}
        device = device or {}
        prompt = prompts.get(run.get("prompt_id")) if run.get("prompt_id") else {}
        prompt = prompt or {}
        model  = run.get("model") or {}
        scores = run.get("scores") or []

        n_preds    = sum(1 for s in scores if s.get("predicted_cpe"))
        n_exact    = sum(1 for s in scores if s.get("exact_match"))
        n_cve_ok   = sum(1 for s in scores if s.get("cve_lookup_valid"))

        rows.append({
            "model_run_id":         run.get("_id"),
            "device_code":          device.get("device_code"),
            "scan_id":              run.get("scan_id"),
            "model_name":           model.get("name"),
            "model_version":        model.get("version"),
            "prompt_name":          prompt.get("prompt_name"),
            "prompt_version":       prompt.get("prompt_version"),
            "temperature":          model.get("temperature"),
            "top_p":                model.get("top_p"),
            "seed":                 model.get("seed"),
            "trial_number":         run.get("trial_number"),
            "doubled":              run.get("doubled"),
            "status":               run.get("status"),
            "started_at":           run.get("started_at"),
            "ended_at":             run.get("ended_at"),
            "error_text":           run.get("error"),
            "n_predictions_scored": n_preds,
            "n_exact":              n_exact,
            "n_cve_valid":          n_cve_ok,
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["device_code", "model_name", "model_run_id"]).reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Aggregation helpers (unchanged logic — just read from the new wide DF)
# ---------------------------------------------------------------------------

def compute_summary_by_model(scores_df):
    if scores_df.empty:
        return pd.DataFrame()

    g = scores_df.groupby(["device_code", "model_name", "doubled"], dropna=False)
    out = g.agg(
        n_predictions=("model_run_id", "count"),
        n_runs=("model_run_id", "nunique"),
        avg_match_score=("match_score", "mean"),
        exact_match_rate=("exact_match", "mean"),
        cve_valid_rate=("cve_lookup_valid", "mean"),
        vendor_correct_rate=("vendor_correct", "mean"),
        product_correct_rate=("product_correct", "mean"),
        version_correct_rate=("version_correct", "mean"),
        part_correct_rate=("part_correct", "mean"),
    ).reset_index()

    hall = g.apply(
        lambda df: (df["best_match_tier"] == "none").mean(),
        include_groups=False,
    ).reset_index(name="no_match_rate")
    out = out.merge(hall, on=["device_code", "model_name", "doubled"])

    return out.round(4)


def compute_summary_by_prompt(scores_df):
    if scores_df.empty:
        return pd.DataFrame()

    g = scores_df.groupby(
        ["model_name", "prompt_name", "prompt_version", "doubled"], dropna=False
    )
    out = g.agg(
        n_predictions=("model_run_id", "count"),
        n_runs=("model_run_id", "nunique"),
        n_devices=("device_code", "nunique"),
        avg_match_score=("match_score", "mean"),
        exact_match_rate=("exact_match", "mean"),
        cve_valid_rate=("cve_lookup_valid", "mean"),
        vendor_correct_rate=("vendor_correct", "mean"),
        product_correct_rate=("product_correct", "mean"),
    ).reset_index()

    return out.round(4)


def compute_variance_by_config(scores_df):
    if scores_df.empty:
        return pd.DataFrame()

    per_run = (
        scores_df
        .groupby(
            ["scan_id", "model_name", "prompt_id", "temperature", "doubled", "model_run_id"],
            dropna=False,
        )["match_score"]
        .mean()
        .reset_index(name="run_avg_match_score")
    )

    g = per_run.groupby(
        ["scan_id", "model_name", "prompt_id", "temperature", "doubled"],
        dropna=False,
    )
    out = g.agg(
        n_trials=("model_run_id", "count"),
        mean_match_score=("run_avg_match_score", "mean"),
        stdev_match_score=("run_avg_match_score", "std"),
        min_match_score=("run_avg_match_score", "min"),
        max_match_score=("run_avg_match_score", "max"),
    ).reset_index()

    return out.round(4)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Export scoring data to xlsx")
    parser.add_argument(
        "--out",
        default=None,
        help="Output file path. Default: exports/<timestamp>.xlsx",
    )
    args = parser.parse_args()

    ensure_db()
    db = get_db()

    print("  Building scores_wide...")
    scores_df = build_scores_wide(db)
    print(f"    {len(scores_df)} scored prediction row(s)")

    print("  Building run manifest...")
    manifest_df = build_run_manifest(db)
    print(f"    {len(manifest_df)} model_run row(s)")

    if scores_df.empty:
        print("\nWARNING: no scored predictions found. Run scores.py first.")

    print("  Computing aggregations...")
    summary_by_model_df  = compute_summary_by_model(scores_df)
    summary_by_prompt_df = compute_summary_by_prompt(scores_df)
    variance_df          = compute_variance_by_config(scores_df)

    if args.out:
        out_path = Path(args.out)
    else:
        EXPORTS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = EXPORTS_DIR / f"thesis_export_{ts}.xlsx"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"  Writing {out_path}...")
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        scores_df.to_excel(writer,            sheet_name="scores_wide",        index=False)
        summary_by_model_df.to_excel(writer,  sheet_name="summary_by_model",   index=False)
        summary_by_prompt_df.to_excel(writer, sheet_name="summary_by_prompt",  index=False)
        variance_df.to_excel(writer,          sheet_name="variance_by_config", index=False)
        manifest_df.to_excel(writer,          sheet_name="run_manifest",       index=False)

    print(f"\nDone. Sheets written: scores_wide ({len(scores_df)}), "
          f"summary_by_model ({len(summary_by_model_df)}), "
          f"summary_by_prompt ({len(summary_by_prompt_df)}), "
          f"variance_by_config ({len(variance_df)}), "
          f"run_manifest ({len(manifest_df)})")


if __name__ == "__main__":
    main()

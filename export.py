#!/usr/bin/env python3
"""
Export scoring data to a single multi-sheet xlsx file.

Produces five sheets:
  - scores_wide       : one row per scored prediction (atomic facts)
  - summary_by_model  : metrics grouped by (device_code, model_name)
  - summary_by_prompt : metrics grouped by (model_name, prompt_name+version)
  - variance_by_config: metrics grouped by (agg_input_id, model_name, prompt_id, temperature)
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

from db import ensure_db, get_connection


EXPORTS_DIR = Path(__file__).parent / "exports"


# ---------------------------------------------------------------------------
# The atomic query — one row per scored prediction with every column joined in
# ---------------------------------------------------------------------------

SCORES_WIDE_SQL = """
SELECT
    -- Device context
    d.id                    AS device_id,
    d.device_code,
    d.manufacturer          AS device_manufacturer,
    d.model                 AS device_model,
    d.device_type,

    -- Scan context
    ss.id                   AS scan_session_id,
    ss.target_ip,
    ss.hostname             AS scan_hostname,
    sr.scan_name,
    sr.tool_version         AS nmap_version,

    -- Aggregated input context
    ai.id                   AS aggregated_input_id,
    ai.variant_name         AS input_variant,
    ai.parser_version       AS input_parser_version,

    -- Model run context
    mr.id                   AS model_run_id,
    mr.model_name,
    mr.model_version,
    mr.temperature,
    mr.top_p,
    mr.max_tokens,
    mr.seed,
    mr.trial_number,
    mr.status               AS run_status,
    mr.started_at           AS run_started_at,
    mr.ended_at             AS run_ended_at,

    -- Prompt context
    p.id                    AS prompt_id,
    p.prompt_name,
    p.prompt_version,

    -- Ground truth context
    gt.id                   AS ground_truth_id,
    gt.true_vendor,
    gt.true_product,
    gt.true_firmware_version,
    gt.rubric_version,
    gt.label_status,

    -- The prediction
    s.id                    AS score_id,
    s.predicted_cpe,
    s.predicted_vendor,
    s.predicted_product,
    s.matched_accepted_cpe,

    -- Field-level correctness
    s.part_correct,
    s.vendor_correct,
    s.product_correct,
    s.version_correct,

    -- Aggregated correctness
    s.exact_match,
    s.cve_lookup_valid,
    s.best_match_tier,
    s.match_score,
    s.score_notes,
    s.scorer_version,
    s.created_at            AS scored_at

FROM scores s
JOIN model_runs mr          ON mr.id = s.model_run_id
JOIN aggregated_inputs ai   ON ai.id = mr.aggregated_input_id
JOIN scan_sessions ss       ON ss.id = ai.scan_session_id
JOIN devices d              ON d.id = ss.device_id
JOIN ground_truth gt        ON gt.id = s.ground_truth_id
LEFT JOIN prompts p         ON p.id = mr.prompt_id
LEFT JOIN scan_runs sr      ON sr.scan_session_id = ss.id
ORDER BY d.device_code, mr.model_name, mr.id, s.id
"""


# ---------------------------------------------------------------------------
# One row per model_run — lets you see error runs, empty-output runs, etc.
# ---------------------------------------------------------------------------

RUN_MANIFEST_SQL = """
SELECT
    mr.id                   AS model_run_id,
    d.device_code,
    ai.id                   AS aggregated_input_id,
    mr.model_name,
    mr.model_version,
    p.prompt_name,
    p.prompt_version,
    mr.temperature,
    mr.top_p,
    mr.seed,
    mr.trial_number,
    mr.status,
    mr.started_at,
    mr.ended_at,
    mr.error_text,
    COUNT(s.id)             AS n_predictions_scored,
    SUM(s.exact_match)      AS n_exact,
    SUM(s.cve_lookup_valid) AS n_cve_valid
FROM model_runs mr
JOIN aggregated_inputs ai   ON ai.id = mr.aggregated_input_id
JOIN scan_sessions ss       ON ss.id = ai.scan_session_id
JOIN devices d              ON d.id = ss.device_id
LEFT JOIN prompts p         ON p.id = mr.prompt_id
LEFT JOIN scores s          ON s.model_run_id = mr.id
GROUP BY mr.id
ORDER BY d.device_code, mr.model_name, mr.id
"""


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def compute_summary_by_model(scores_df):
    """Per (device_code, model_name): rates and averages across all predictions."""
    if scores_df.empty:
        return pd.DataFrame()

    g = scores_df.groupby(["device_code", "model_name"], dropna=False)
    out = g.agg(
        n_predictions=("score_id", "count"),
        n_runs=("model_run_id", "nunique"),
        avg_match_score=("match_score", "mean"),
        exact_match_rate=("exact_match", "mean"),
        cve_valid_rate=("cve_lookup_valid", "mean"),
        vendor_correct_rate=("vendor_correct", "mean"),
        product_correct_rate=("product_correct", "mean"),
        version_correct_rate=("version_correct", "mean"),
        part_correct_rate=("part_correct", "mean"),
    ).reset_index()

    # Hallucination candidate rate = fraction with best_match_tier='none'
    hall = g.apply(
        lambda df: (df["best_match_tier"] == "none").mean(),
        include_groups=False,
    ).reset_index(name="no_match_rate")
    out = out.merge(hall, on=["device_code", "model_name"])

    return out.round(4)


def compute_summary_by_prompt(scores_df):
    """Per (model_name, prompt_name, prompt_version): same metrics, averaged over all devices."""
    if scores_df.empty:
        return pd.DataFrame()

    g = scores_df.groupby(
        ["model_name", "prompt_name", "prompt_version"], dropna=False
    )
    out = g.agg(
        n_predictions=("score_id", "count"),
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
    """Per (agg_input, model, prompt, temp): trial count, mean/stdev/min/max match_score.

    Collapses per-prediction rows to per-run match_score means first, so
    variance is measured across runs, not across individual predictions.
    """
    if scores_df.empty:
        return pd.DataFrame()

    # First: one match_score per model_run (mean of its predictions)
    per_run = (
        scores_df
        .groupby(
            ["aggregated_input_id", "model_name", "prompt_id", "temperature", "model_run_id"],
            dropna=False,
        )["match_score"]
        .mean()
        .reset_index(name="run_avg_match_score")
    )

    # Then: variance across runs for a given configuration
    g = per_run.groupby(
        ["aggregated_input_id", "model_name", "prompt_id", "temperature"],
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
    con = get_connection()

    print("  Loading atomic scores...")
    scores_df = pd.read_sql_query(SCORES_WIDE_SQL, con)
    print(f"    {len(scores_df)} scored prediction row(s)")

    print("  Loading run manifest...")
    manifest_df = pd.read_sql_query(RUN_MANIFEST_SQL, con)
    print(f"    {len(manifest_df)} model_run row(s)")

    con.close()

    if scores_df.empty:
        print("\nWARNING: no scored predictions found. Run scores.py first.")

    print("  Computing aggregations...")
    summary_by_model_df  = compute_summary_by_model(scores_df)
    summary_by_prompt_df = compute_summary_by_prompt(scores_df)
    variance_df          = compute_variance_by_config(scores_df)

    # Resolve output path
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
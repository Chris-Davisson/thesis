#!/usr/bin/env python3
"""
Generate thesis-aligned PNGs and print the backing result tables.

This is intentionally smaller than export_thesis_data.py. It does not rebuild
the XLSX. It uses the same filtered dataframe logic as export_thesis_data.py,
then renders 01_model_comparison.png from that exact dataframe and prints the
tables most commonly cited in the Results prose.

Usage:
    python make_thesis_png_tables.py
    python make_thesis_png_tables.py --out-dir Documents/final_writeup/img
    python make_thesis_png_tables.py --tables-output exports/thesis_tables.txt
    python make_thesis_png_tables.py --no-filter
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from analyze import (
    build_dataframe,
    compute_model_table,
    connect_db,
    load_config,
    plot_model_comparison,
)
from archive.export_thesis_data import (
    EXCLUDED_DEVICES,
    EXCLUDED_MODELS,
    _filter_for_thesis,
    agg_01_model_comparison,
    agg_08_scan_type,
    agg_16_hallucination_index,
)


def _llm(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["prompt_name"] != "nmap_baseline"].copy()


def _fmt_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "(empty)"

    out = df.copy()
    for col in out.columns:
        if pd.api.types.is_float_dtype(out[col]):
            out[col] = out[col].map(lambda v: "" if pd.isna(v) else f"{v:.4f}")
    return out.to_string(index=False)


def _section(title: str, df: pd.DataFrame | None = None, text: str | None = None) -> str:
    lines = ["", "=" * len(title), title, "=" * len(title)]
    if text:
        lines.append(text)
    if df is not None:
        lines.append(_fmt_table(df))
    return "\n".join(lines)


def overview_table(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    return pd.DataFrame([
        ("rows_total", len(df)),
        ("rows_llm", len(llm)),
        ("runs_total", df["run_id"].nunique()),
        ("runs_llm", llm["run_id"].nunique()),
        ("models_llm", llm["model_short"].nunique()),
        ("devices", df["device_code"].nunique()),
        ("overall_llm_mean", llm["match_score"].mean()),
        ("overall_llm_halluc_rate", llm["is_hallucination"].mean()),
        ("overall_llm_halluc_count", int(llm["is_hallucination"].sum())),
    ], columns=["metric", "value"])


def family_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    return (
        llm.groupby("model_family")
        .agg(
            mean_score=("match_score", "mean"),
            exact_rate=("exact_match", "mean"),
            halluc_rate=("is_hallucination", "mean"),
            vendor_acc=("vendor_correct", "mean"),
            product_acc=("product_correct", "mean"),
            n_models=("model_short", "nunique"),
            n=("match_score", "count"),
        )
        .reset_index()
        .sort_values("mean_score", ascending=False)
        .reset_index(drop=True)
    )


def prompt_summary(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    return (
        llm.groupby("prompt_name")
        .agg(
            mean_score=("match_score", "mean"),
            exact_rate=("exact_match", "mean"),
            halluc_rate=("is_hallucination", "mean"),
            vendor_acc=("vendor_correct", "mean"),
            product_acc=("product_correct", "mean"),
            n=("match_score", "count"),
        )
        .reset_index()
        .sort_values("mean_score", ascending=False)
        .reset_index(drop=True)
    )


def prompt_axis_effects(df: pd.DataFrame) -> pd.DataFrame:
    llm = prompt_2x2_factorial(df)
    if llm.empty:
        return pd.DataFrame()
    structured = llm.groupby("structured")["match_score"].mean()
    persona = llm.groupby("persona")["match_score"].mean()
    rows = []
    if {"minimal", "structured"}.issubset(structured.index):
        rows.append((
            "structured_minus_minimal",
            structured["structured"],
            structured["minimal"],
            structured["structured"] - structured["minimal"],
        ))
    if {"persona", "neutral"}.issubset(persona.index):
        rows.append((
            "persona_minus_neutral",
            persona["persona"],
            persona["neutral"],
            persona["persona"] - persona["neutral"],
        ))
    return pd.DataFrame(rows, columns=["effect", "with_feature", "without_feature", "delta"])


def prompt_2x2_factorial(df: pd.DataFrame) -> pd.DataFrame:
    prompts = {
        "neutral_minimal",
        "neutral_structured",
        "persona_minimal",
        "persona_structured",
    }
    llm = _llm(df)
    return llm[llm["prompt_name"].isin(prompts)].copy()


def prompt_2x2_table(df: pd.DataFrame) -> pd.DataFrame:
    sub = prompt_2x2_factorial(df)
    if sub.empty:
        return pd.DataFrame()
    return (
        sub.groupby(["persona", "structured"])
        .agg(mean_score=("match_score", "mean"), n=("match_score", "count"))
        .reset_index()
        .sort_values(["persona", "structured"])
        .reset_index(drop=True)
    )


def doubled_overall(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    # Match the thesis comparison: only models with both doubled modes, and no
    # OpenAI/Anthropic rows that were not run under doubled mode.
    both_mode_models = llm.groupby("model_short")["doubled"].nunique()
    keep = both_mode_models[both_mode_models == 2].index
    sub = llm[
        llm["model_short"].isin(keep)
        & ~llm["model_family"].isin(["Claude", "GPT"])
    ]
    if sub.empty:
        return pd.DataFrame()
    grouped = sub.groupby("doubled")["match_score"].agg(["mean", "count"])
    normal = grouped.loc[False, "mean"] if False in grouped.index else np.nan
    doubled = grouped.loc[True, "mean"] if True in grouped.index else np.nan
    return pd.DataFrame([{
        "normal": normal,
        "doubled": doubled,
        "delta_doubled_minus_normal": doubled - normal,
        "n_normal": int(grouped.loc[False, "count"]) if False in grouped.index else 0,
        "n_doubled": int(grouped.loc[True, "count"]) if True in grouped.index else 0,
    }])


def doubled_by_family(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    both_mode_models = llm.groupby("model_short")["doubled"].nunique()
    keep = both_mode_models[both_mode_models == 2].index
    sub = llm[
        llm["model_short"].isin(keep)
        & ~llm["model_family"].isin(["Claude", "GPT"])
    ]
    if sub.empty:
        return pd.DataFrame()
    pivot = sub.groupby(["model_family", "doubled"])["match_score"].mean().unstack()
    out = pd.DataFrame({
        "model_family": pivot.index,
        "normal": pivot[False] if False in pivot.columns else np.nan,
        "doubled": pivot[True] if True in pivot.columns else np.nan,
    }).reset_index(drop=True)
    out["delta_doubled_minus_normal"] = out["doubled"] - out["normal"]
    return out.sort_values("delta_doubled_minus_normal", ascending=False).reset_index(drop=True)


def configured_scan_suites(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    suites = llm[llm["scan_name"].astype(str).str.match(r"^\d{2}-", na=False)]
    return (
        suites.groupby("scan_name")
        .agg(
            mean_score=("match_score", "mean"),
            exact_rate=("exact_match", "mean"),
            halluc_rate=("is_hallucination", "mean"),
            vendor_acc=("vendor_correct", "mean"),
            product_acc=("product_correct", "mean"),
            n=("match_score", "count"),
        )
        .reset_index()
        .sort_values("mean_score", ascending=False)
        .reset_index(drop=True)
    )


def deployment_tier(row: pd.Series) -> str:
    model_short = str(row["model_short"]).lower()
    family = str(row["model_family"])
    if "cloud" in model_short:
        return "Ollama Cloud"
    if family in {"GPT", "Claude", "Gemini"}:
        return "Frontier (API)"
    return "Local (vLLM)"


def deployment_summary(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    sub = llm.assign(deployment=llm.apply(deployment_tier, axis=1))
    return (
        sub.groupby("deployment")
        .agg(
            mean_score=("match_score", "mean"),
            exact_rate=("exact_match", "mean"),
            halluc_rate=("is_hallucination", "mean"),
            vendor_acc=("vendor_correct", "mean"),
            product_acc=("product_correct", "mean"),
            n_models=("model_short", "nunique"),
            n=("match_score", "count"),
        )
        .reset_index()
        .sort_values("mean_score", ascending=False)
        .reset_index(drop=True)
    )


def best_of_tier(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    per_model = (
        llm.assign(deployment=llm.apply(deployment_tier, axis=1))
        .groupby(["deployment", "model_short"])
        .agg(mean_score=("match_score", "mean"), halluc_rate=("is_hallucination", "mean"))
        .reset_index()
        .sort_values(["deployment", "mean_score"], ascending=[True, False])
    )
    return per_model.groupby("deployment", as_index=False).head(1).reset_index(drop=True)


def securityllm_check(df: pd.DataFrame) -> pd.DataFrame:
    llm = _llm(df)
    sec = llm[llm["model_short"].eq("SecurityLLM")]
    if sec.empty:
        return pd.DataFrame()
    has_pred = sec["predicted_cpe"].fillna("").astype(bool)
    runs = sec["run_id"].nunique()
    pred_runs = sec.loc[has_pred, "run_id"].nunique()
    return pd.DataFrame([{
        "rows": len(sec),
        "runs": runs,
        "pred_rows": int(has_pred.sum()),
        "pred_runs": pred_runs,
        "pred_run_rate": pred_runs / runs if runs else np.nan,
        "mean_score": sec["match_score"].mean(),
        "halluc_rate": sec["is_hallucination"].mean(),
        "product_acc": sec["product_correct"].mean(),
    }])


def collect_tables(df: pd.DataFrame) -> list[tuple[str, pd.DataFrame | None, str | None]]:
    return [
        ("Overview", overview_table(df), None),
        ("00_model_table", compute_model_table(df), None),
        ("01_model_comparison", agg_01_model_comparison(df), None),
        ("Family Breakdown (row-weighted)", family_breakdown(df), None),
        ("Prompt Summary", prompt_summary(df), None),
        ("Prompt 2x2 (factorial prompts only)", prompt_2x2_table(df), None),
        ("Prompt Axis Effects", prompt_axis_effects(df), None),
        ("Doubled Overall", doubled_overall(df), None),
        ("Doubled By Family", doubled_by_family(df), None),
        ("Configured Scan Suites", configured_scan_suites(df), None),
        ("All Scan Names", agg_08_scan_type(df), None),
        ("Deployment Summary", deployment_summary(df), None),
        ("Best Of Tier", best_of_tier(df), None),
        ("Hallucination Index", agg_16_hallucination_index(df), None),
        ("SecurityLLM Sanity Check", securityllm_check(df), None),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate thesis-filtered 01_model_comparison.png and print backing tables."
    )
    parser.add_argument("--config", default="config.toml")
    parser.add_argument(
        "--out-dir",
        default="Documents/final_writeup/img",
        help="Directory for generated PNGs (default: Documents/final_writeup/img)",
    )
    parser.add_argument(
        "--tables-output",
        default=None,
        help="Optional text file path for the printed table dump.",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Use raw build_dataframe output instead of export_thesis_data._filter_for_thesis.",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    db = connect_db(cfg)

    print("Loading data from MongoDB...")
    df_raw = build_dataframe(db)
    print(f"  raw rows: {len(df_raw):,}")

    if args.no_filter:
        df = df_raw.reset_index(drop=True)
        filter_text = "NO FILTER"
    else:
        df = _filter_for_thesis(df_raw)
        filter_text = (
            "trial == 1; "
            f"excluded_models={sorted(EXCLUDED_MODELS)}; "
            f"excluded_devices={sorted(EXCLUDED_DEVICES)}"
        )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_model_comparison(df, out_dir)
    print(f"Generated {out_dir / '01_model_comparison.png'}")

    sections = [
        _section("Source", text=f"filter: {filter_text}\nrows: {len(df):,}")
    ]
    for title, frame, text in collect_tables(df):
        sections.append(_section(title, frame, text))

    output = "\n".join(sections).strip() + "\n"
    print(output)

    if args.tables_output:
        path = Path(args.tables_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()

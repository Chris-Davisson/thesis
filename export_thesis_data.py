#!/usr/bin/env python3
"""
export_thesis_data.py — Export chart-ready aggregated tables to a single .xlsx.

Architecture:
  - `00_predictions_long`  : the canonical flat analysis dataset, one row per
                             predicted CPE. Filtered to the experimental matrix
                             described in Chapter 5 (see _filter_for_thesis).
  - `00_runs_long`         : one row per model_run, aggregated up from the
                             predictions frame.
  - 01..NN                 : pre-baked pivots, each mapped to a planned thesis
                             figure. Every one is derivable from
                             `00_predictions_long`.

Filtering rule (applied at the source, before any aggregation):
  - trial == 1 only (the unguided arm; RQ3 was inconclusive — see Chapter 7).
  - kimi-k2.6:cloud and qwen3.5:cloud excluded (>70% empty responses from
    Ollama Cloud).
  - Nintendo_WiiU and WiFi_Repeater_Repeater_Mode excluded (no usable ground
    truth — see Chapter 5 §Ground Truth Labeling).

Use `--no-filter` to skip the exclusions (diagnostic only; not what the thesis
cites). Use `--include-raw` to also dump the unfiltered predictions frame as
a parallel sheet for auditability.

Usage:
    python export_thesis_data.py
    python export_thesis_data.py --output exports/thesis_data.xlsx
    python export_thesis_data.py --no-filter        # skip Chapter 5 exclusions
    python export_thesis_data.py --include-raw      # also dump unfiltered df
"""

import argparse
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from analyze import (
    FAMILY_ORDER,
    TIER_ORDER,
    build_dataframe,
    compute_model_table,
    compute_summary,
    connect_db,
    load_config,
)


# ── Filter for the Chapter 5 experimental matrix ───────────────────────────────

# Models excluded because Ollama Cloud returned empty bodies for >70% of
# invocations. See Chapter 5 §Inference Configuration §Ollama Cloud Models.
EXCLUDED_MODELS = { "qwen3.5:cloud"}

# Devices excluded from quantitative results. Wii U scan was signal-poor;
# Repeater_Mode scan had no usable MAC (off-segment ARP). See Chapter 5
# §Ground Truth Labeling.
EXCLUDED_DEVICES = {"Nintendo_WiiU", "WiFi_Repeater_Repeater_Mode"}


def _filter_for_thesis(df):
    """Restrict df to the experimental matrix described in Chapter 5.

    The four rules that this enforces are documented in the chapter; applying
    them here at the source rather than per-sheet means every aggregation
    downstream describes the same matrix the thesis prose promises.
    """
    n0 = len(df)
    out = df[df["trial"] == 1]                                          # unguided only
    out = out[~out["model_short"].isin(EXCLUDED_MODELS)]
    out = out[~out["device_code"].isin(EXCLUDED_DEVICES)]
    print(f"  filter_for_thesis: kept {len(out):,} of {n0:,} predictions "
          f"({100 * len(out) / max(n0, 1):.1f}%)")
    return out.reset_index(drop=True)


# ── Aggregation helpers ────────────────────────────────────────────────────────

def _fam_map(df):
    return (df.drop_duplicates("model_short")
              .set_index("model_short")["model_family"]
              .to_dict())


def _llm(df):
    return df[df["prompt_name"] != "nmap_baseline"]


def _families_present(df):
    fams = set(df["model_family"].unique())
    return [f for f in FAMILY_ORDER if f in fams]


def _attach_family(agg, df, model_col="model_short"):
    fam = _fam_map(df)
    agg.insert(1, "family", agg[model_col].map(fam))
    return agg


def _five_number(s):
    s = s.dropna()
    if s.empty:
        return dict(n=0, mean=np.nan, std=np.nan,
                    min=np.nan, q1=np.nan, median=np.nan, q3=np.nan, max=np.nan)
    return dict(
        n=int(len(s)),
        mean=float(s.mean()),
        std=float(s.std(ddof=1)) if len(s) > 1 else 0.0,
        min=float(s.min()),
        q1=float(s.quantile(0.25)),
        median=float(s.median()),
        q3=float(s.quantile(0.75)),
        max=float(s.max()),
    )


# ── Flat analysis tables (canonical source for every other sheet) ──────────────

def agg_predictions_long(df):
    """One row per predicted CPE — the canonical analysis dataset."""
    return df.reset_index(drop=True)


def agg_runs_long(df):
    """One row per model_run, aggregated from the predictions frame.

    Caveat: runs that produced zero predicted CPEs do not appear here because
    they have no rows in the predictions frame. To inspect empty runs, query
    MongoDB directly against the model_runs collection.
    """
    if "run_id" not in df.columns:
        return pd.DataFrame()
    g = df.groupby("run_id", observed=True, dropna=False)
    out = g.agg(
        scan_id        =("scan_id",          "first"),
        device_code    =("device_code",      "first"),
        prompt_name    =("prompt_name",      "first"),
        model_short    =("model_short",      "first"),
        model_family   =("model_family",     "first"),
        doubled        =("doubled",          "first"),
        trial          =("trial",            "first"),
        temperature    =("temperature",      "first"),
        seed           =("seed",             "first"),
        guided         =("guided",           "first"),
        payload_chars  =("payload_chars",    "first"),
        n_predictions  =("match_score",      "count"),
        mean_score     =("match_score",      "mean"),
        max_score      =("match_score",      "max"),
        any_exact      =("exact_match",      "max"),
        any_cve_valid  =("cve_valid",        "max"),
        any_halluc     =("is_hallucination", "max"),
        raw_clean_json =("raw_clean_json",   "first"),
    ).reset_index()
    return out.sort_values(["model_short", "scan_id", "prompt_name", "doubled"],
                            kind="mergesort").reset_index(drop=True)


# ── Per-chart aggregations ─────────────────────────────────────────────────────

def agg_01_model_comparison(df):
    g = df.groupby("model_short")["match_score"]
    out = pd.DataFrame({
        "model_short": g.mean().index,
        "mean_score":  g.mean().values,
        "sem":         (g.std() / np.sqrt(g.count().clip(lower=1))).values,
        "n":           g.count().values,
    })
    return _attach_family(out.sort_values("mean_score", ascending=False)
                             .reset_index(drop=True), df)


def agg_02_field_accuracy(df):
    fields = ["vendor_correct", "product_correct", "version_correct"]
    out = (df.groupby("model_short")[fields].mean().reset_index())
    out["n"] = df.groupby("model_short").size().values
    out = out.rename(columns={"vendor_correct": "vendor_acc",
                              "product_correct": "product_acc",
                              "version_correct": "version_acc"})
    out = out.sort_values("vendor_acc", ascending=False).reset_index(drop=True)
    return _attach_family(out, df)


def agg_03_tier_breakdown(df):
    counts = (df.groupby(["model_short", "best_tier"], observed=True)
                .size().unstack(fill_value=0)
                .reindex(columns=TIER_ORDER, fill_value=0))
    n = counts.sum(axis=1)
    frac = counts.div(n.replace(0, np.nan), axis=0)
    frac["n"] = n.astype(int)
    frac = frac.reset_index()
    frac = frac.sort_values("exact", ascending=False).reset_index(drop=True)
    return _attach_family(frac, df)


def agg_04_score_distribution(df):
    rows = []
    for m, sub in df.groupby("model_short"):
        s = _five_number(sub["match_score"])
        s["model_short"] = m
        rows.append(s)
    out = pd.DataFrame(rows)
    out = out[["model_short", "n", "mean", "std",
               "min", "q1", "median", "q3", "max"]]
    out = out.sort_values("mean", ascending=False).reset_index(drop=True)
    return _attach_family(out, df)


def agg_05_prompt_ablation(df):
    llm = _llm(df)
    panel_a = (llm.groupby(["persona", "structured"])["match_score"]
                  .agg(["mean", "count"]).reset_index()
                  .rename(columns={"mean": "mean_score", "count": "n"}))
    panel_a_pivot = (panel_a.pivot(index="persona", columns="structured",
                                   values="mean_score").reset_index())

    panel_b = (llm.groupby(["prompt_name", "model_short"])["match_score"]
                  .agg(["mean", "count"]).reset_index()
                  .rename(columns={"mean": "mean_score", "count": "n"}))
    panel_b_pivot = (panel_b.pivot(index="model_short", columns="prompt_name",
                                   values="mean_score").reset_index())
    panel_b_pivot = _attach_family(panel_b_pivot, df)
    return {
        "Panel A — Persona × Structured (long)":  panel_a,
        "Panel A — Persona × Structured (pivot)": panel_a_pivot,
        "Panel B — Prompt × Model (pivot)":       panel_b_pivot,
    }


def agg_06_doubled_effect(df):
    llm = _llm(df)
    pivot = (llm.groupby(["model_short", "doubled"])["match_score"]
                .agg(["mean", "count"]).unstack())
    out = pd.DataFrame({
        "model_short": pivot.index,
        "normal":      pivot[("mean",  False)].values if ("mean",  False) in pivot.columns else np.nan,
        "doubled":     pivot[("mean",  True)].values  if ("mean",  True)  in pivot.columns else np.nan,
        "n_normal":    pivot[("count", False)].astype("Int64").values if ("count", False) in pivot.columns else 0,
        "n_doubled":   pivot[("count", True)].astype("Int64").values  if ("count", True)  in pivot.columns else 0,
    })
    out["delta_doubled_minus_normal"] = out["doubled"] - out["normal"]
    out = out.sort_values("normal", ascending=False).reset_index(drop=True)
    return _attach_family(out, df)


def agg_07_device_heatmap(df):
    pivot = (df.groupby(["device_code", "model_short"])["match_score"]
                .mean().unstack())
    model_order = pivot.mean().sort_values(ascending=False).index.tolist()
    device_order = pivot.mean(axis=1).sort_values(ascending=False).index.tolist()
    pivot = pivot.loc[device_order, model_order].reset_index()
    return pivot


def agg_08_scan_type(df):
    pivot = (df.groupby(["scan_name", "model_short"])["match_score"]
                .mean().unstack())
    model_order = pivot.mean().sort_values(ascending=False).index.tolist()
    scan_order = pivot.mean(axis=1).sort_values(ascending=False).index.tolist()
    pivot = pivot.loc[scan_order, model_order].reset_index()
    return pivot


def agg_09_exact_and_cve(df):
    out = (df.groupby("model_short")
             .agg(exact_rate=("exact_match", "mean"),
                  cve_rate=("cve_valid",     "mean"),
                  n=("match_score", "count"))
             .reset_index()
             .sort_values("exact_rate", ascending=False)
             .reset_index(drop=True))
    return _attach_family(out, df)


def agg_10_trial_variance(df):
    llm = _llm(df)
    rows = []
    for t, sub in llm.groupby("trial"):
        s = _five_number(sub["match_score"])
        s["trial"] = int(t)
        rows.append(s)
    out = pd.DataFrame(rows)
    out = out[["trial", "n", "mean", "std",
               "min", "q1", "median", "q3", "max"]]
    return out.sort_values("trial").reset_index(drop=True)


def agg_11_consistency_delta(df):
    llm = _llm(df)
    pivot = (llm.groupby(["model_short", "doubled"])["match_score"]
                .agg(["mean", "count"]).unstack())
    out = pd.DataFrame({
        "model_short": pivot.index,
        "single":      pivot[("mean",  False)].values if ("mean",  False) in pivot.columns else np.nan,
        "doubled":     pivot[("mean",  True)].values  if ("mean",  True)  in pivot.columns else np.nan,
        "n_single":    pivot[("count", False)].astype("Int64").values if ("count", False) in pivot.columns else 0,
        "n_doubled":   pivot[("count", True)].astype("Int64").values  if ("count", True)  in pivot.columns else 0,
    })
    out["delta_doubled_minus_single"] = out["doubled"] - out["single"]
    out = out.sort_values("delta_doubled_minus_single").reset_index(drop=True)
    return _attach_family(out, df)


def agg_12_guided_vs_unguided(df):
    llm = _llm(df)
    pivot = (llm.groupby(["model_short", "guided"])["match_score"]
                .agg(["mean", "count"]).unstack())
    score = pd.DataFrame({
        "model_short": pivot.index,
        "unguided":    pivot[("mean",  False)].values if ("mean",  False) in pivot.columns else np.nan,
        "guided":      pivot[("mean",  True)].values  if ("mean",  True)  in pivot.columns else np.nan,
        "n_unguided":  pivot[("count", False)].astype("Int64").values if ("count", False) in pivot.columns else 0,
        "n_guided":    pivot[("count", True)].astype("Int64").values  if ("count", True)  in pivot.columns else 0,
    })
    score["delta_guided_minus_unguided"] = score["guided"] - score["unguided"]
    score = score.sort_values("guided", ascending=False).reset_index(drop=True)
    score = _attach_family(score, df)

    unguided_runs = llm[~llm["guided"]].drop_duplicates("run_id")
    if unguided_runs.empty:
        repair = pd.DataFrame(columns=["model_short", "json_repair_rate", "n_unguided_runs"])
    else:
        rep = unguided_runs.groupby("model_short")["raw_clean_json"]
        repair = pd.DataFrame({
            "model_short":     rep.mean().index,
            "json_repair_rate": (1.0 - rep.mean()).values,
            "n_unguided_runs": rep.count().values,
        }).sort_values("json_repair_rate", ascending=False).reset_index(drop=True)
        repair = _attach_family(repair, df)

    return {
        "Panel A — Score by Guided/Unguided": score,
        "Panel B — JSON Repair Rate (unguided)": repair,
    }


def agg_13_creativity_penalty(df):
    llm = _llm(df)
    agg = (llm.groupby(["model_short", "guided"])
              .agg(vendor=("vendor_correct", "mean"),
                   product=("product_correct", "mean"),
                   n=("match_score", "count"))
              .reset_index())
    if agg["guided"].nunique() < 2:
        return agg
    pivot = agg.pivot(index="model_short", columns="guided",
                      values=["vendor", "product", "n"])
    pivot.columns = [f"{m}_{'guided' if g else 'unguided'}"
                     for m, g in pivot.columns]
    pivot = pivot.reset_index().sort_values("vendor_unguided", ascending=False) \
                 .reset_index(drop=True)
    return _attach_family(pivot, df)


def agg_14_temperature_sensitivity(df):
    llm = _llm(df)
    grp = (llm.groupby(["model_short", "temperature", "scan_id", "prompt_name"])
              ["match_score"].agg(["std", "count"]).reset_index())
    grp = grp[grp["count"] >= 2].dropna(subset=["std"])
    summary = (grp.groupby(["model_short", "temperature"])["std"]
                  .mean().reset_index()
                  .rename(columns={"std": "mean_within_group_std"}))
    pivot = summary.pivot(index="model_short", columns="temperature",
                          values="mean_within_group_std").reset_index()
    return _attach_family(pivot, df)


def agg_15_accuracy_funnel(df):
    llm = _llm(df)
    fields = ["part_correct", "vendor_correct",
              "product_correct", "version_correct"]
    out = (llm.groupby("model_short")[fields].mean().reset_index()
              .rename(columns={"part_correct": "part",
                               "vendor_correct": "vendor",
                               "product_correct": "product",
                               "version_correct": "version"}))
    out["n"] = llm.groupby("model_short").size().values
    out = out.sort_values("vendor", ascending=False).reset_index(drop=True)
    return _attach_family(out, df)


def agg_16_hallucination_index(df):
    llm = _llm(df)
    has_pred = llm["predicted_cpe"].fillna("").astype(bool)
    vendor_only = (has_pred & (llm["vendor_correct"] == 1)
                            & (llm["product_correct"] == 0)).astype(int)
    out = (pd.DataFrame({
                "model_short":        llm["model_short"].values,
                "is_hallucination":   llm["is_hallucination"].values,
                "vendor_only_invent": vendor_only.values,
            })
            .groupby("model_short")
            .agg(total_halluc_rate=("is_hallucination", "mean"),
                 vendor_only_invent_rate=("vendor_only_invent", "mean"),
                 n=("is_hallucination", "count"))
            .reset_index()
            .sort_values("total_halluc_rate", ascending=False)
            .reset_index(drop=True))
    return _attach_family(out, df)


def agg_17_payload_vs_score(df):
    llm = _llm(df)
    if llm["payload_chars"].nunique() < 5:
        return llm[["model_short", "payload_chars", "match_score"]] \
                .reset_index(drop=True)
    bins = pd.qcut(llm["payload_chars"], q=5, duplicates="drop")
    bin_labels = [f"{int(b.left):,}-{int(b.right):,}"
                  for b in bins.cat.categories]
    binned = (llm.assign(_bin=bins)
                  .groupby(["model_short", "_bin"], observed=True)["match_score"]
                  .agg(["mean", "count"]).reset_index())
    pivot = binned.pivot(index="model_short", columns="_bin", values="mean")
    pivot.columns = bin_labels
    pivot = pivot.reset_index().sort_values(bin_labels[0], ascending=False) \
                 .reset_index(drop=True)
    return _attach_family(pivot, df)


def agg_18_intensity_performance(df):
    llm = _llm(df)
    llm = llm[llm["intensity"].notna()]
    pivot = (llm.groupby(["model_short", "intensity"])["match_score"]
                 .mean().unstack().reset_index())
    return _attach_family(pivot, df)


def agg_19_vendor_bias(df):
    llm = _llm(df)
    pivot = (llm.groupby(["manufacturer", "model_short"])["match_score"]
                 .mean().unstack())
    model_order = pivot.mean().sort_values(ascending=False).index.tolist()
    vendor_order = pivot.mean(axis=1).sort_values(ascending=False).index.tolist()
    return pivot.loc[vendor_order, model_order].reset_index()


def agg_20_baseline_lift(df):
    llm = df[(df["prompt_name"] != "nmap_baseline") & df["baseline_lift"].notna()]
    out = (llm.groupby("model_short")["baseline_lift"]
              .agg(mean_lift="mean", n="count")
              .reset_index()
              .sort_values("mean_lift", ascending=False)
              .reset_index(drop=True))
    return _attach_family(out, df)


def agg_21_family_summary(df):
    llm = _llm(df)
    per_model = (llm.groupby(["model_family", "model_short"])["match_score"]
                    .mean().reset_index())
    rows = []
    for fam, sub in per_model.groupby("model_family"):
        stats = _five_number(sub["match_score"])
        stats["model_family"] = fam
        stats["n_models"] = int(sub["model_short"].nunique())
        rows.append(stats)
    out = pd.DataFrame(rows)
    out = out[["model_family", "n_models", "mean", "std",
               "min", "q1", "median", "q3", "max"]]
    return out.sort_values("mean", ascending=False).reset_index(drop=True)


def agg_22_metric_correlation(df):
    cols = ["match_score", "exact_match", "vendor_correct", "product_correct",
            "version_correct", "cve_valid", "is_hallucination",
            "raw_clean_json", "payload_chars"]
    cols = [c for c in cols if c in df.columns]
    sub = df[cols].apply(pd.to_numeric, errors="coerce").dropna()
    corr = sub.corr(method="pearson")
    return corr.reset_index().rename(columns={"index": "metric"})


def agg_23_size_scaling(df):
    llm = _llm(df)
    out = (llm.groupby(["model_short", "model_family"])
              .agg(mean_score=("match_score", "mean"),
                   size_b=("model_size_b", "first"),
                   active_size_b=("model_active_size_b", "first"),
                   is_cloud=("is_cloud", "first"),
                   n=("match_score", "count"))
              .reset_index()
              .rename(columns={"model_family": "family"})
              .sort_values(["size_b", "mean_score"],
                           ascending=[True, False])
              .reset_index(drop=True))
    return out


def agg_24_hallucination_drivers(df):
    llm = _llm(df)
    fams = [f for f in FAMILY_ORDER
            if f in llm["model_family"].unique() and f != "Baseline"]

    panels = {}

    if llm["guided"].nunique() >= 2:
        a = (llm.groupby(["model_family", "guided"])
                .agg(halluc=("is_hallucination", "mean"),
                     n=("is_hallucination", "count"))
                .reset_index())
        a_pv = a.pivot(index="model_family", columns="guided",
                       values=["halluc", "n"])
        a_pv.columns = [f"{m}_{'guided' if g else 'unguided'}"
                        for m, g in a_pv.columns]
        a_pv = a_pv.reindex(fams).reset_index()
        panels["Panel A — Hallucination by Guided"] = a_pv

    if llm["doubled"].nunique() >= 2:
        b = (llm.groupby(["model_family", "doubled"])
                .agg(halluc=("is_hallucination", "mean"),
                     n=("is_hallucination", "count"))
                .reset_index())
        b_pv = b.pivot(index="model_family", columns="doubled",
                       values=["halluc", "n"])
        b_pv.columns = [f"{m}_{'doubled' if d else 'single'}"
                        for m, d in b_pv.columns]
        b_pv = b_pv.reindex(fams).reset_index()
        panels["Panel B — Hallucination by Doubled"] = b_pv

    if llm["temperature"].nunique() >= 2:
        c = (llm.groupby(["model_family", "temperature"])
                ["is_hallucination"].mean().reset_index())
        c_pv = c.pivot(index="model_family", columns="temperature",
                       values="is_hallucination").reindex(fams).reset_index()
        panels["Panel C — Hallucination by Temperature"] = c_pv

    if llm["payload_chars"].nunique() >= 4:
        bins = pd.qcut(llm["payload_chars"], q=5, duplicates="drop")
        labels = [f"{int(b.left):,}-{int(b.right):,}"
                  for b in bins.cat.categories]
        d = (llm.assign(_bin=bins)
                .groupby(["model_family", "_bin"], observed=True)
                ["is_hallucination"].mean().reset_index())
        d_pv = d.pivot(index="model_family", columns="_bin",
                       values="is_hallucination")
        d_pv.columns = labels
        d_pv = d_pv.reindex(fams).reset_index()
        panels["Panel D — Hallucination by Payload Quintile"] = d_pv

    return panels


def agg_25_cloud_vs_local(df):
    llm = _llm(df)
    fams = [f for f in FAMILY_ORDER
            if f in llm["model_family"].unique() and f != "Baseline"]
    agg = (llm.groupby(["model_family", "is_cloud"])
              .agg(score=("match_score", "mean"),
                   halluc=("is_hallucination", "mean"),
                   n_models=("model_short", "nunique"))
              .reset_index())
    pivot = agg.pivot(index="model_family", columns="is_cloud",
                      values=["score", "halluc", "n_models"])
    pivot.columns = [f"{m}_{'cloud' if c else 'local'}"
                     for m, c in pivot.columns]
    pivot = pivot.reindex(fams).reset_index()
    return pivot


def agg_26_model_variants(df):
    """
    Per-model breakdown by sampling / decoding variant. One row per unique
    (model_short, temperature, seed, doubled, guided) combination, LLM-only.
    Lets you graph variant-level deltas (temp/seed/doubled/guided) that the
    model-level sheets collapse together.
    """
    llm = _llm(df).copy()
    # `seed` can be None on runs that didn't pass one — represent as "—" so
    # groupby keeps the bucket instead of dropping it.
    llm["seed"] = llm["seed"].where(llm["seed"].notna(), other="—")

    keys = ["model_short", "temperature", "seed", "doubled", "guided"]
    grp = llm.groupby(keys, dropna=False)

    out = grp.agg(
        n_predictions     =("match_score",      "count"),
        n_runs            =("run_id",           "nunique"),
        mean_score        =("match_score",      "mean"),
        std_score         =("match_score",      "std"),
        exact_rate        =("exact_match",      "mean"),
        vendor_acc        =("vendor_correct",   "mean"),
        product_acc       =("product_correct",  "mean"),
        version_acc       =("version_correct",  "mean"),
        halluc_rate       =("is_hallucination", "mean"),
        cve_rate          =("cve_valid",        "mean"),
        mean_baseline_lift=("baseline_lift",    "mean"),
    ).reset_index()

    out["sem"] = out["std_score"] / np.sqrt(out["n_predictions"].clip(lower=1))
    out = out.drop(columns=["std_score"])

    # Flag rows whose model has more than one variant — easier to filter in Excel.
    variants_per_model = out.groupby("model_short").size()
    out["has_variants"] = out["model_short"].map(variants_per_model > 1)

    out = out.sort_values(
        ["model_short", "temperature", "seed", "doubled", "guided"],
        kind="mergesort",
    ).reset_index(drop=True)

    return _attach_family(out, df)


# ── Excel writing ──────────────────────────────────────────────────────────────

def _write_single(writer, sheet_name, df):
    df.to_excel(writer, sheet_name=sheet_name, index=False)


def _write_blocks(writer, sheet_name, blocks: dict):
    """Write multiple labelled DataFrames stacked in one sheet."""
    row = 0
    for label, frame in blocks.items():
        pd.DataFrame([[label]]).to_excel(writer, sheet_name=sheet_name,
                                         index=False, header=False,
                                         startrow=row, startcol=0)
        frame.to_excel(writer, sheet_name=sheet_name, index=False,
                       startrow=row + 1)
        row += len(frame) + 3  # label + col headers + body + blank line


def _write_overview(writer, df, summary, model_table, filter_applied=True):
    excluded_models = ", ".join(sorted(EXCLUDED_MODELS)) if filter_applied else "(none — filter disabled)"
    excluded_devices = ", ".join(sorted(EXCLUDED_DEVICES)) if filter_applied else "(none — filter disabled)"
    headline = pd.DataFrame([
        ("n_models",      summary["n_models"]),
        ("n_devices",     summary["n_devices"]),
        ("n_runs",        summary["n_runs"]),
        ("n_predictions", summary["n_preds"]),
        ("n_empty_runs",  summary["n_empty_runs"]),
        ("overall_mean_score", round(summary["overall_score"], 4)),
        ("overall_exact_rate", round(summary["exact_rate"], 4)),
        ("best_model",         summary["best_model"]),
        ("hallucination_rate", round(summary["halluc_rate"], 4)),
        ("mean_baseline_lift", round(summary["mean_lift"], 4)),
        ("json_repair_rate",   round(summary["repair_rate"], 4)),
        ("filter_applied",     "yes (trial==1, excluded models, excluded devices)" if filter_applied else "NO — raw export"),
        ("excluded_models",    excluded_models),
        ("excluded_devices",   excluded_devices),
        ("trial_filter",       "trial == 1" if filter_applied else "(none)"),
        ("export_timestamp",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ], columns=["metric", "value"])

    toc = pd.DataFrame([
        ("00_predictions_long",      "Canonical analysis dataset: one row per predicted CPE (filtered to the Chapter 5 experimental matrix)"),
        ("00_runs_long",             "One row per model_run, aggregated from predictions_long (empty runs omitted)"),
        ("01_model_comparison",      "Mean match score per model (with SEM, n)"),
        ("02_field_accuracy",        "Vendor / product / version accuracy per model"),
        ("03_tier_breakdown",        "Match-tier distribution (exact/partial/related/none)"),
        ("05_prompt_ablation",       "Persona × Structured ablation (3 blocks)"),
        ("06_doubled_effect",        "Normal vs Doubled prompt mode per model"),
        ("07_device_heatmap",        "Device × Model match-score pivot"),
        ("08_scan_type",             "Scan-name × Model match-score pivot"),
        ("09_exact_and_cve",         "Exact-match and CVE-valid rates per model"),
        ("15_accuracy_funnel",       "Part → Vendor → Product → Version per model"),
        ("16_hallucination_index",   "Total halluc + vendor-only-invent per model"),
        ("20_baseline_lift",         "Mean per-scan lift over nmap baseline"),
        ("21_family_summary",        "5-number summary of family means"),
        ("23_size_scaling",          "Param-count vs mean score per model"),
        ("25_cloud_vs_local",        "Family-level cloud vs local comparison"),
    ], columns=["sheet", "what's in it"])

    headline.to_excel(writer, sheet_name="00_overview", index=False, startrow=0)
    pd.DataFrame([["Sheet index"]]).to_excel(writer, sheet_name="00_overview",
                                             index=False, header=False,
                                             startrow=len(headline) + 2)
    toc.to_excel(writer, sheet_name="00_overview", index=False,
                 startrow=len(headline) + 3)

    model_table.to_excel(writer, sheet_name="00_model_table", index=False)


# ── Driver ─────────────────────────────────────────────────────────────────────

# The thesis-aligned chart set. Each entry maps to a planned figure or table
# in Chapter 6 (Results) or Chapter 7 (Discussion). Anything that requires
# guided trials, the empty-output Ollama Cloud models, or the unscorable
# devices has been culled — those analyses are no longer meaningful once
# _filter_for_thesis runs.
#
# Aggregations retained from the original 26 but not in this list are still
# defined in this file (agg_04, agg_10, agg_11, agg_12, agg_13, agg_14,
# agg_17, agg_18, agg_19, agg_22, agg_24, agg_26). They can be re-added to
# this list if a specific Discussion-chapter argument needs them.
CHARTS = [
    ("01_model_comparison",       agg_01_model_comparison),
    ("02_field_accuracy",         agg_02_field_accuracy),
    ("03_tier_breakdown",         agg_03_tier_breakdown),
    ("05_prompt_ablation",        agg_05_prompt_ablation),
    ("06_doubled_effect",         agg_06_doubled_effect),
    ("07_device_heatmap",         agg_07_device_heatmap),
    ("08_scan_type",              agg_08_scan_type),
    ("09_exact_and_cve",          agg_09_exact_and_cve),
    ("15_accuracy_funnel",        agg_15_accuracy_funnel),
    ("16_hallucination_index",    agg_16_hallucination_index),
    ("20_baseline_lift",          agg_20_baseline_lift),
    ("21_family_summary",         agg_21_family_summary),
    ("23_size_scaling",           agg_23_size_scaling),
    ("25_cloud_vs_local",         agg_25_cloud_vs_local),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config.toml")
    p.add_argument("--output", default=None,
                   help="Path to .xlsx (default: exports/thesis_data_<ts>.xlsx)")
    p.add_argument("--no-filter", action="store_true",
                   help="Skip the Chapter 5 exclusions (diagnostic only; not what the thesis cites)")
    p.add_argument("--include-raw", action="store_true",
                   help="Also dump the unfiltered predictions frame as 00_predictions_long_raw")
    args = p.parse_args()

    cfg = load_config(args.config)
    db  = connect_db(cfg)
    print("Loading data from MongoDB...")
    df_raw = build_dataframe(db)
    print(f"  {len(df_raw):,} prediction rows loaded.")

    filter_applied = not args.no_filter
    if filter_applied:
        df = _filter_for_thesis(df_raw)
    else:
        print("  --no-filter set; using unfiltered dataframe.")
        df = df_raw

    out = Path(args.output) if args.output else \
          Path("exports") / f"thesis_data_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    out.parent.mkdir(parents=True, exist_ok=True)

    summary     = compute_summary(df)
    model_table = compute_model_table(df)

    print(f"Writing {out} ...")
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        _write_overview(writer, df, summary, model_table, filter_applied=filter_applied)

        # Flat tables first — these are the canonical source of truth for the
        # thesis. The pivots below are documented conveniences derived from them.
        predictions_long = agg_predictions_long(df)
        _write_single(writer, "00_predictions_long", predictions_long)
        print(f"  ✓ 00_predictions_long ({len(predictions_long):,} rows)")

        runs_long = agg_runs_long(df)
        if not runs_long.empty:
            _write_single(writer, "00_runs_long", runs_long)
            print(f"  ✓ 00_runs_long ({len(runs_long):,} rows)")

        if args.include_raw and filter_applied:
            raw_long = agg_predictions_long(df_raw)
            _write_single(writer, "00_predictions_long_raw", raw_long)
            print(f"  ✓ 00_predictions_long_raw ({len(raw_long):,} rows, unfiltered)")

        for sheet, fn in CHARTS:
            try:
                result = fn(df)
            except Exception as exc:
                print(f"  ✗ {sheet}: {exc}")
                continue
            if isinstance(result, dict):
                if not result:
                    print(f"  • {sheet}: no panels (skipped)")
                    continue
                _write_blocks(writer, sheet, result)
                print(f"  ✓ {sheet} ({len(result)} blocks)")
            elif isinstance(result, pd.DataFrame):
                if result.empty:
                    print(f"  • {sheet}: empty (skipped)")
                    continue
                _write_single(writer, sheet, result)
                print(f"  ✓ {sheet} ({len(result)} rows)")
            else:
                print(f"  ✗ {sheet}: unexpected return type {type(result)}")

    print(f"\nDone. Open {out} in Excel.")


if __name__ == "__main__":
    main()

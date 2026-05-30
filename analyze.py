#!/usr/bin/env python3
"""
analyze.py — LLM CPE-prediction benchmark analysis & visualisation.

Reads scored model_runs from MongoDB (config via config.toml), generates
PNG plots and a self-contained HTML report.

Usage:
    python analyze.py
    python analyze.py --output exports/my_analysis
    python analyze.py --config /path/to/config.toml
"""

import argparse
import base64
import io
import json
import re
import sys
import tomllib
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
from pymongo import MongoClient

# ── Visual constants ───────────────────────────────────────────────────────────

plt.rcParams.update({
    "figure.dpi": 150,
    "figure.facecolor": "white",
    "axes.facecolor": "#f8f9fa",
    "axes.grid": True,
    "grid.color": "white",
    "grid.linewidth": 1.4,
    "font.family": "sans-serif",
    "font.size": 10,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.spines.left": False,
    "axes.spines.bottom": False,
    "xtick.bottom": False,
    "ytick.left": False,
    "legend.framealpha": 0.9,
    "legend.edgecolor": "#dee2e6",
    "legend.fontsize": 9,
})

BLUE   = "#4361ee"
RED    = "#e63946"
GREEN  = "#2dc653"
ORANGE = "#f4a261"
PURPLE = "#7b2d8b"
GRAY   = "#adb5bd"
TEAL   = "#2ec4b6"
NAVY   = "#1d3557"

TIER_COLORS = {
    "exact":   GREEN,
    "partial": ORANGE,
    "related": PURPLE,
    "none":    GRAY,
}
TIER_ORDER = ["exact", "partial", "related", "none"]

MODEL_PALETTE = [
    "#4361ee", "#e63946", "#2dc653", "#f4a261",
    "#7b2d8b", "#2ec4b6", "#1d3557", "#f72585",
    "#06d6a0", "#ffd166", "#118ab2", "#ef476f",
]

# Family colors — one consistent color per architecture so models read at a glance
FAMILY_COLORS = {
    "Llama":    "#4361ee",
    "Qwen":     "#7b2d8b",
    "Gemma":    "#2dc653",
    "Mistral":  "#e63946",
    "Phi":      "#f4a261",
    "DeepSeek": "#2ec4b6",
    "Granite":  "#118ab2",
    "GLM":      "#06d6a0",
    "Kimi":     "#ffd166",
    "GPT-OSS":  "#1d3557",
    "GPT":      "#10a37f",   # OpenAI frontier (gpt-5.x)
    "Claude":   "#d97757",   # Anthropic frontier
    "Gemini":   "#8e75d8",   # Google frontier
    "SecTuned": "#f72585",
    "Other":    "#adb5bd",
    "Baseline": "#495057",
}

# Order families left→right (or top→bottom). Open-weight families first
# (ordered by rough release recency / scale), then frontier APIs, then the
# auxiliary buckets at the end.
FAMILY_ORDER = [
    "Llama", "Qwen", "Gemma", "Mistral", "Phi", "DeepSeek",
    "Granite", "GLM", "Kimi", "GPT-OSS",
    "GPT", "Claude", "Gemini",
    "SecTuned", "Other", "Baseline",
]


def _model_family(name: str) -> str:
    """Coarse architecture family from a model_short string.

    Match order matters: SecTuned overrides base-architecture matches because
    several SecTuned models (Llama-Primus, WhiteRabbitNeo-Qwen, etc.) carry
    base-architecture keywords in their names but should be grouped by their
    fine-tuning lineage rather than their base. Likewise, GPT-OSS is matched
    before the generic GPT rule because `openai/gpt-oss-20b` contains both.
    """
    s = (name or "").lower()
    if "nmap" in s:                                                return "Baseline"
    if ("whiterabbit" in s or "zysec" in s or "securityllm" in s
            or "foundation-sec" in s or "primus" in s):            return "SecTuned"
    if "llama" in s:                                                return "Llama"
    if "qwen" in s:                                                 return "Qwen"
    if "gemma" in s:                                                return "Gemma"
    if "mistral" in s or "ministral" in s:                          return "Mistral"
    if "phi" in s:                                                  return "Phi"
    if "deepseek" in s:                                             return "DeepSeek"
    if "granite" in s:                                              return "Granite"
    if "glm" in s:                                                  return "GLM"
    if "kimi" in s:                                                 return "Kimi"
    if "claude" in s or "anthropic" in s:                           return "Claude"
    if "gemini" in s:                                               return "Gemini"
    if "gpt-oss" in s:                                              return "GPT-OSS"
    if "gpt" in s or s.startswith("openai/"):                       return "GPT"
    return "Other"


_SIZE_TRILLION_RE = re.compile(r"(\d+(?:\.\d+)?)t\b")
_SIZE_MOE_RE      = re.compile(r"(\d+)x(\d+(?:\.\d+)?)b\b")
_SIZE_BILLION_RE  = re.compile(r"(\d+(?:\.\d+)?)b\b")

_MODEL_SIZES_PATH = Path(__file__).parent / "model_sizes.json"
_MODEL_SIZES_CACHE: dict | None = None


def _load_model_sizes() -> dict:
    """Read model_sizes.json once and memoize. Empty dict if missing."""
    global _MODEL_SIZES_CACHE
    if _MODEL_SIZES_CACHE is None:
        if _MODEL_SIZES_PATH.exists():
            with open(_MODEL_SIZES_PATH, encoding="utf-8") as f:
                _MODEL_SIZES_CACHE = json.load(f)
        else:
            _MODEL_SIZES_CACHE = {}
    return _MODEL_SIZES_CACHE


def _lookup_size_entry(name: str) -> dict | None:
    """Find a size entry by exact full name, or by short-name suffix match."""
    if not name:
        return None
    sizes = _load_model_sizes()
    entry = sizes.get(name)
    if entry is not None:
        return entry
    # Allow callers passing model_short (basename) instead of the full name.
    for full, e in sizes.items():
        if full.split("/")[-1] == name or full.endswith("/" + name):
            return e
    return None


def _regex_size(name: str):
    """Fallback: parse parameter count (B) from name tokens like '7b', '1t', '8x7b'."""
    s = (name or "").lower()
    m = _SIZE_TRILLION_RE.search(s)
    if m:
        return float(m.group(1)) * 1000.0
    m = _SIZE_MOE_RE.search(s)
    if m:
        return float(m.group(1)) * float(m.group(2))
    m = _SIZE_BILLION_RE.search(s)
    if m:
        return float(m.group(1))
    return None


def _model_size(name: str):
    """Total parameter count in billions. Looks up `name` in model_sizes.json
    first (authoritative, hand-curated for cloud / proprietary / fine-tune
    models the regex cannot parse), falling back to regex parsing on the name."""
    entry = _lookup_size_entry(name)
    if entry is not None:
        return entry.get("total_b")
    return _regex_size(name)


def _model_active_size(name: str):
    """Active parameter count in billions (smaller than total for MoE).
    Falls back to total size when active is not catalogued."""
    entry = _lookup_size_entry(name)
    if entry is not None:
        active = entry.get("active_b")
        return active if active is not None else entry.get("total_b")
    return _regex_size(name)


def _is_cloud(name: str) -> bool:
    return ":cloud" in (name or "").lower()


# ── Config & DB ────────────────────────────────────────────────────────────────

def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def connect_db(cfg: dict):
    client = MongoClient(cfg["database"]["uri"], serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
    except Exception as exc:
        print(f"ERROR: cannot reach MongoDB — {exc}")
        sys.exit(1)
    return client[cfg["database"]["name"]]


# ── Data loading ───────────────────────────────────────────────────────────────

_INTENSITY_RE = re.compile(r"^(\d+)")


def _parse_intensity(scan_name: str):
    """Extract leading integer from scan_name (e.g. '01-sv-osc-top1000' → 1)."""
    if not scan_name:
        return np.nan
    m = _INTENSITY_RE.match(scan_name)
    return int(m.group(1)) if m else np.nan


def _looks_like_clean_json(raw: str) -> bool:
    """Return whether the model produced a standalone JSON object.

    Flags the response as needing repair if there is any
    text before the first '{' or after the last '}', or if json.loads fails.
    """
    if not raw:
        return False
    s = raw.strip()
    if not s.startswith("{") or not s.endswith("}"):
        return False
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def build_dataframe(db) -> pd.DataFrame:
    """Flatten model_runs + scores + scan + device + prompt into one DataFrame."""

    scans = {s["_id"]: s for s in db.scans.find(
        {}, {"_id": 1, "device_id": 1, "nmap.scan_name": 1, "payload": 1})}
    devices = {d["_id"]: d for d in db.devices.find(
        {}, {"_id": 1, "device_code": 1, "manufacturer": 1})}
    prompts = {p["_id"]: p for p in db.prompts.find(
        {}, {"_id": 1, "prompt_name": 1})}

    rows = []
    for run in db.model_runs.find({"status": "complete"}):
        scan = scans.get(run.get("scan_id"), {})
        device = devices.get(scan.get("device_id"), {})
        prompt = prompts.get(run.get("prompt_id"), {})
        scores = run.get("scores") or []
        model_meta = run.get("model", {}) or {}
        raw_output = run.get("raw_output") or ""
        payload = scan.get("payload") or ""
        scan_name = scan.get("nmap", {}).get("scan_name", "unknown")

        base = {
            "run_id":       run["_id"],
            "scan_id":      run.get("scan_id"),
            "model":        model_meta.get("name", "unknown"),
            "prompt_name":  prompt.get("prompt_name", "nmap_baseline"),
            "doubled":      bool(run.get("doubled", False)),
            "trial":        run.get("trial_number", 1),
            "scan_name":    scan_name,
            "device_code":  device.get("device_code", "unknown"),
            "manufacturer": device.get("manufacturer", "unknown"),
            # Sampling / decoding parameters (guard against stored nulls)
            "temperature":  float(model_meta.get("temperature") or 0.0),
            "seed":         model_meta.get("seed", None),
            "guided":       bool(model_meta.get("guided_decoding") or False),
            # Density / format-compliance signals (per-run, repeated across rows)
            "payload_chars":  len(payload),
            "intensity":      _parse_intensity(scan_name),
            "raw_output":     raw_output,
            "raw_clean_json": _looks_like_clean_json(raw_output),
        }

        if not scores:
            rows.append({**base,
                         "predicted_cpe":  None,
                         "part_correct":   0,
                         "vendor_correct": 0,
                         "product_correct": 0,
                         "version_correct": 0,
                         "exact_match":    0,
                         "cve_valid":      0,
                         "match_score":    0.0,
                         "best_tier":      "none"})
        else:
            for s in scores:
                rows.append({**base,
                             "predicted_cpe":   s.get("predicted_cpe", ""),
                             "part_correct":    int(s.get("part_correct",    0)),
                             "vendor_correct":  int(s.get("vendor_correct",  0)),
                             "product_correct": int(s.get("product_correct", 0)),
                             "version_correct": int(s.get("version_correct", 0)),
                             "exact_match":     int(s.get("exact_match",     0)),
                             "cve_valid":       int(s.get("cve_lookup_valid", 0)),
                             "match_score":     float(s.get("match_score",   0.0)),
                             "best_tier":       s.get("best_match_tier",     "none"),
                             })

    if not rows:
        print("ERROR: no complete runs found in the database.")
        sys.exit(1)

    df = pd.DataFrame(rows)
    df["model_short"]  = df["model"].str.split("/").str[-1].str[:35]
    df["model_family"] = df["model_short"].apply(_model_family)
    df["model_size_b"]        = df["model"].apply(_model_size)
    df["model_active_size_b"] = df["model"].apply(_model_active_size)
    df["is_cloud"]            = df["model"].apply(_is_cloud)
    df["persona"]     = df["prompt_name"].apply(
        lambda x: "persona" if "persona" in x else "neutral")
    df["structured"]  = df["prompt_name"].apply(
        lambda x: "structured" if "structured" in x else "minimal")
    df["best_tier"]   = pd.Categorical(
        df["best_tier"], categories=TIER_ORDER, ordered=True)

    # ── Derived columns ───────────────────────────────────────────────────
    # Hallucination: model emitted a CPE with an incorrect vendor and an
    # overall score of zero. (predicted_cpe truthy AND vendor_correct=0
    # AND match_score=0)
    df["is_hallucination"] = (
        df["predicted_cpe"].fillna("").astype(bool)
        & (df["vendor_correct"] == 0)
        & (df["match_score"] == 0.0)
    ).astype(int)

    # Precision gap: how far a partial match is from being exact.
    # 0 means already exact; 1 means nothing matched.
    df["precision_gap"] = (1.0 - df["match_score"]).clip(lower=0.0)

    # Baseline lift: per-(scan, device) lift over nmap baseline.
    # Computed by joining each LLM row to the mean baseline score for the
    # same scan_id; missing baseline → NaN (excluded from lift averages).
    baseline_mask = df["prompt_name"] == "nmap_baseline"
    if baseline_mask.any():
        baseline_score = (df[baseline_mask]
                          .groupby("scan_id")["match_score"]
                          .mean()
                          .rename("_baseline_score"))
        df = df.merge(baseline_score, on="scan_id", how="left")
        df["baseline_lift"] = df["match_score"] - df["_baseline_score"]
        df.loc[baseline_mask, "baseline_lift"] = np.nan  # Baseline rows have no lift.
        df = df.drop(columns=["_baseline_score"])
    else:
        df["baseline_lift"] = np.nan

    return df


# ── Plot helpers ───────────────────────────────────────────────────────────────

def _model_colors(models):
    return {m: MODEL_PALETTE[i % len(MODEL_PALETTE)] for i, m in enumerate(models)}


def _model_to_family(df: pd.DataFrame) -> dict:
    """Mapping model_short → family from a dataframe (uses first occurrence)."""
    return (df.drop_duplicates("model_short")
              .set_index("model_short")["model_family"]
              .to_dict())


def _model_order_by_family(df: pd.DataFrame, score_col: str = "match_score",
                           ascending: bool = False) -> list:
    """Order models: families by mean score, then within-family by mean score.

    ascending=True returns the reversed order — useful for matplotlib's barh
    which plots the first item at the bottom (so to put the best at the top,
    pass ascending=True).
    """
    fam_mean = (df.groupby("model_family")[score_col].mean()
                  .sort_values(ascending=ascending))
    out = []
    for fam in fam_mean.index:
        models = (df[df["model_family"] == fam]
                  .groupby("model_short")[score_col].mean()
                  .sort_values(ascending=ascending).index.tolist())
        out.extend(models)
    return out


def _bar_colors_by_family(models, fam_map: dict) -> list:
    return [FAMILY_COLORS.get(fam_map.get(m, "Other"), "#adb5bd") for m in models]


def _family_legend(ax, families_present, **kwargs):
    """Compact family legend (multi-column) for plots with many models."""
    from matplotlib.patches import Patch
    handles = [Patch(color=FAMILY_COLORS[f], label=f) for f in families_present
               if f in FAMILY_COLORS]
    if not handles:
        return
    ncol = max(1, min(4, (len(handles) + 2) // 3))
    defaults = dict(loc="lower right", ncol=ncol, fontsize=8,
                    framealpha=0.95, title="Family", title_fontsize=8)
    defaults.update(kwargs)
    ax.legend(handles=handles, **defaults)


def _families_present(df: pd.DataFrame, models=None) -> list:
    """Return families in display order (FAMILY_ORDER) that appear in df/models."""
    if models is not None:
        fams = set(df[df["model_short"].isin(models)]["model_family"].unique())
    else:
        fams = set(df["model_family"].unique())
    return [f for f in FAMILY_ORDER if f in fams]


def _save(fig, path: Path) -> str:
    """Save fig to path, return base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    data = buf.getvalue()
    path.write_bytes(data)
    plt.close(fig)
    return base64.b64encode(data).decode()


# ── Plots ──────────────────────────────────────────────────────────────────────

def plot_model_comparison(df: pd.DataFrame, out: Path) -> str:
    """Horizontal bar: mean match_score per model, grouped & colored by family."""
    agg = (df.groupby("model_short")
             .agg(mean=("match_score", "mean"),
                  sem=("match_score",  lambda x: x.std() / np.sqrt(max(len(x), 1))))
             .reset_index())

    fam_map = _model_to_family(df)
    order = _model_order_by_family(df, "match_score", ascending=True)
    agg = agg.set_index("model_short").reindex(order).reset_index()

    bar_colors = _bar_colors_by_family(agg["model_short"], fam_map)

    fig, ax = plt.subplots(figsize=(10, max(4, len(agg) * 0.36)))
    bars = ax.barh(agg["model_short"], agg["mean"],
                   xerr=agg["sem"], capsize=2,
                   color=bar_colors, edgecolor="white", linewidth=0.4,
                   error_kw={"elinewidth": 1.0, "ecolor": "#495057"})
    for bar, score in zip(bars, agg["mean"]):
        ax.text(bar.get_width() + 0.005, bar.get_y() + bar.get_height() / 2,
                f"{score:.3f}", va="center", fontsize=8, color="#495057")

    ax.set_xlim(0, 1.18)
    ax.xaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
    ax.set_xlabel("Mean Match Score (± SEM)")
    ax.set_title("Model Performance — Mean CPE Match Score (grouped by family)")
    ax.tick_params(axis="y", labelsize=8)

    _family_legend(ax, _families_present(df, agg["model_short"].tolist()))
    fig.tight_layout()
    return _save(fig, out / "01_model_comparison.png")


def plot_field_accuracy(df: pd.DataFrame, out: Path) -> str:
    """Grouped bar: vendor / product / version accuracy per model."""
    fields  = ["vendor_correct", "product_correct", "version_correct"]
    labels  = ["Vendor", "Product", "Version"]
    fcolors = [BLUE, ORANGE, GREEN]

    agg = (df.groupby("model_short")[fields]
             .mean()
             .sort_values("vendor_correct", ascending=False)
             .reset_index())

    x = np.arange(len(agg))
    w = 0.26
    fig, ax = plt.subplots(figsize=(max(8, len(agg) * 1.8), 5))
    for i, (field, label, color) in enumerate(zip(fields, labels, fcolors)):
        rects = ax.bar(x + (i - 1) * w, agg[field], w,
                       label=label, color=color, edgecolor="white", linewidth=0.4)
        for r in rects:
            h = r.get_height()
            ax.text(r.get_x() + r.get_width() / 2, h + 0.01,
                    f"{h:.0%}", ha="center", va="bottom", fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels(agg["model_short"], rotation=30, ha="right")
    ax.set_ylim(0, 1.18)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_ylabel("Accuracy")
    ax.set_title("CPE Field Accuracy by Model")
    ax.legend(loc="upper right")
    fig.tight_layout()
    return _save(fig, out / "02_field_accuracy.png")


def plot_tier_breakdown(df: pd.DataFrame, out: Path) -> str:
    """Stacked horizontal bar: match-tier distribution per model, family-grouped."""
    agg = (df.groupby(["model_short", "best_tier"], observed=True)
             .size()
             .unstack(fill_value=0)
             .reindex(columns=TIER_ORDER, fill_value=0))
    frac = agg.div(agg.sum(axis=1), axis=0)

    order = _model_order_by_family(df, "match_score", ascending=True)
    frac  = frac.reindex(order)
    fam_map = _model_to_family(df)

    fig, ax = plt.subplots(figsize=(11, max(4, len(frac) * 0.36)))
    left = np.zeros(len(frac))
    for tier in TIER_ORDER:
        if tier not in frac.columns:
            continue
        vals = frac[tier].values
        ax.barh(frac.index, vals, left=left,
                label=tier.capitalize(),
                color=TIER_COLORS[tier], edgecolor="white", linewidth=0.4)
        for j, (v, l) in enumerate(zip(vals, left)):
            if v > 0.06:
                ax.text(l + v / 2, j, f"{v:.0%}",
                        ha="center", va="center", fontsize=7.5,
                        color="white", fontweight="bold")
        left += vals

    # Color y-tick labels by family so the family is still legible at a glance
    for tick, model in zip(ax.get_yticklabels(), frac.index):
        tick.set_color(FAMILY_COLORS.get(fam_map.get(model, "Other"), "#212529"))
        tick.set_fontsize(8)

    ax.set_xlim(0, 1.01)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_xlabel("Fraction of Predictions")
    ax.set_title("Match Tier Distribution by Model (label color = family)")
    ax.legend(loc="lower right", ncol=4, fontsize=8, title="Tier", title_fontsize=8)
    fig.tight_layout()
    return _save(fig, out / "03_tier_breakdown.png")


def plot_score_distribution(df: pd.DataFrame, out: Path) -> str:
    """Violin + strip: match_score distribution per model."""
    order = (df.groupby("model_short")["match_score"]
               .mean()
               .sort_values(ascending=False)
               .index.tolist())
    colors = _model_colors(order)
    pal = {m: GRAY if "nmap" in m.lower() else colors[m] for m in order}

    fig, ax = plt.subplots(figsize=(max(8, len(order) * 1.5), 5))
    sns.violinplot(data=df, x="model_short", y="match_score",
                   hue="model_short", order=order, inner="box",
                   palette=pal, ax=ax, cut=0, linewidth=0.8,
                   legend=False)
    ax.set_ylim(-0.05, 1.12)
    ax.set_ylabel("Match Score")
    ax.set_xlabel("")
    ax.set_title("CPE Match Score Distribution by Model")
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    return _save(fig, out / "04_score_distribution.png")


def plot_prompt_ablation(df: pd.DataFrame, out: Path) -> str:
    """2×2 heatmap: persona × structure → mean match_score."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["persona"].nunique() < 2 and llm["structured"].nunique() < 2:
        return ""

    pivot = (llm.groupby(["persona", "structured"])["match_score"]
                .mean()
                .unstack())

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Left: heatmap
    ax = axes[0]
    sns.heatmap(pivot, annot=True, fmt=".3f", cmap="YlOrRd",
                vmin=0, vmax=1, linewidths=1, linecolor="white",
                ax=ax, annot_kws={"size": 14, "weight": "bold"},
                cbar_kws={"label": "Mean Match Score"})
    ax.set_title("Prompt Ablation: Persona × Structure")
    ax.set_xlabel("Prompt Structure")
    ax.set_ylabel("Persona Style")

    # Right: per-model breakdown
    ax2 = axes[1]
    pn_order = ["neutral_minimal", "neutral_structured",
                "persona_minimal",  "persona_structured"]
    pn_present = [p for p in pn_order if p in llm["prompt_name"].unique()]
    agg2 = (llm[llm["prompt_name"].isin(pn_present)]
             .groupby(["prompt_name", "model_short"])["match_score"]
             .mean()
             .reset_index())
    model_list = agg2["model_short"].unique()
    mcolors = _model_colors(model_list)
    for m in model_list:
        sub = agg2[agg2["model_short"] == m].set_index("prompt_name")
        sub = sub.reindex(pn_present)
        ax2.plot(range(len(pn_present)), sub["match_score"],
                 marker="o", label=m, color=mcolors[m], linewidth=2)
    ax2.set_xticks(range(len(pn_present)))
    ax2.set_xticklabels([p.replace("_", "\n") for p in pn_present], fontsize=9)
    ax2.set_ylim(0, 1.05)
    ax2.set_ylabel("Mean Match Score")
    ax2.set_title("Score by Prompt Variant per Model")
    ax2.legend(fontsize=8, loc="best")

    fig.tight_layout()
    return _save(fig, out / "05_prompt_ablation.png")


def plot_doubled_effect(df: pd.DataFrame, out: Path) -> str:
    """Side-by-side bar: normal vs doubled prompt mode per model."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["doubled"].nunique() < 2:
        return ""

    agg = (llm.groupby(["model_short", "doubled"])["match_score"]
               .mean()
               .reset_index())
    pivot = agg.pivot(index="model_short", columns="doubled", values="match_score")
    pivot.columns = ["Normal" if not c else "Doubled" for c in pivot.columns]
    if "Normal" not in pivot.columns or "Doubled" not in pivot.columns:
        return ""
    pivot = pivot.sort_values("Normal", ascending=False).reset_index()

    x = np.arange(len(pivot))
    w = 0.35
    fig, ax = plt.subplots(figsize=(max(8, len(pivot) * 1.7), 5))
    b1 = ax.bar(x - w / 2, pivot["Normal"],  w, label="Normal",  color=BLUE,   edgecolor="white")
    b2 = ax.bar(x + w / 2, pivot["Doubled"], w, label="Doubled", color=ORANGE, edgecolor="white")

    for bars in (b1, b2):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(pivot["model_short"], rotation=30, ha="right")
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Mean Match Score")
    ax.set_title("Effect of Doubled Prompt Mode by Model")
    ax.legend()
    fig.tight_layout()
    return _save(fig, out / "06_doubled_effect.png")


def plot_device_heatmap(df: pd.DataFrame, out: Path) -> str:
    """Heatmap: device × model → mean match_score."""
    pivot = (df.groupby(["device_code", "model_short"])["match_score"]
               .mean()
               .unstack())

    model_order = pivot.mean().sort_values(ascending=False).index.tolist()
    device_order = pivot.mean(axis=1).sort_values(ascending=False).index.tolist()
    pivot = pivot.loc[device_order, model_order]

    fig_w = 5
    fig_h = 5
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))

    mask = pivot.isnull()
    sns.heatmap(pivot, annot=False, cmap="RdYlGn",
                vmin=0, vmax=1, linewidths=0, linecolor="white",
                mask=mask, ax=ax,
                cbar=True, cbar_kws={"label": "Mean Match Score", "shrink": 0.6})
    ax.set_title("Mean Match Score — Device × Model")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.xticks(rotation=45, ha="right", fontsize=7)
    plt.yticks(rotation=0, fontsize=7)
    fig.tight_layout()
    return _save(fig, out / "07_device_heatmap.png")


def plot_scan_type(df: pd.DataFrame, out: Path) -> str:
    """Grouped bar: match_score by scan type, split by model."""
    order = (df.groupby("scan_name")["match_score"]
               .mean()
               .sort_values(ascending=False)
               .index.tolist())

    models = (df.groupby("model_short")["match_score"]
                .mean()
                .sort_values(ascending=False)
                .index.tolist())
    mcolors = _model_colors(models)

    x = np.arange(len(order))
    n = len(models)
    w = min(0.8 / n, 0.3)

    fig, ax = plt.subplots(figsize=(max(10, len(order) * 1.5), 5))
    for i, m in enumerate(models):
        sub = (df[df["model_short"] == m]
               .groupby("scan_name")["match_score"]
               .mean()
               .reindex(order, fill_value=np.nan))
        offset = (i - n / 2 + 0.5) * w
        color = GRAY if "nmap" in m.lower() else mcolors[m]
        ax.bar(x + offset, sub.values, w, label=m,
               color=color, edgecolor="white", linewidth=0.3)

    ax.set_xticks(x)
    ax.set_xticklabels(order, rotation=30, ha="right")
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Mean Match Score")
    ax.set_title("Performance by Scan Type")
    ax.legend(loc="upper right", fontsize=8, ncol=2)
    fig.tight_layout()
    return _save(fig, out / "08_scan_type.png")


def plot_exact_and_cve(df: pd.DataFrame, out: Path) -> str:
    """Grouped bar: exact match rate + CVE valid rate per model."""
    agg = (df.groupby("model_short")
             .agg(exact=("exact_match", "mean"),
                  cve=("cve_valid",    "mean"))
             .sort_values("exact", ascending=False)
             .reset_index())

    x = np.arange(len(agg))
    w = 0.35
    fig, ax = plt.subplots(figsize=(max(8, len(agg) * 1.7), 5))
    b1 = ax.bar(x - w / 2, agg["exact"], w, label="Exact Match Rate", color=GREEN, edgecolor="white")
    b2 = ax.bar(x + w / 2, agg["cve"],   w, label="CVE Valid Rate",   color=TEAL,  edgecolor="white")

    for bars in (b1, b2):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{bar.get_height():.1%}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(agg["model_short"], rotation=30, ha="right")
    ax.set_ylim(0, 1.2)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_ylabel("Rate")
    ax.set_title("Exact Match & CVE Validity Rates by Model")
    ax.legend()
    fig.tight_layout()
    return _save(fig, out / "09_exact_and_cve.png")


def plot_trial_variance(df: pd.DataFrame, out: Path) -> str:
    """Box plot: match_score per trial number to assess stochastic variance."""
    if df["trial"].nunique() < 2:
        return ""

    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty:
        return ""

    fig, ax = plt.subplots(figsize=(7, 4))
    trial_order = sorted(llm["trial"].unique())
    llm_copy = llm.copy()
    llm_copy["trial"] = llm_copy["trial"].astype(str)
    sns.boxplot(data=llm_copy, x="trial", y="match_score",
                order=[str(t) for t in trial_order],
                color=BLUE, linewidth=1.2, ax=ax, fliersize=3)
    ax.set_ylim(-0.05, 1.1)
    ax.set_xlabel("Trial Number")
    ax.set_ylabel("Match Score")
    ax.set_title("Score Variance Across Trials (LLM runs only)")
    fig.tight_layout()
    return _save(fig, out / "10_trial_variance.png")


# ── Additional plots: doubling, guided, sampling, hierarchy, density, bias ────

def plot_consistency_delta(df: pd.DataFrame, out: Path) -> str:
    """Bar: Match Score (Doubled) - (Single) per model."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["doubled"].nunique() < 2:
        return ""

    pivot = (llm.groupby(["model_short", "doubled"])["match_score"]
                .mean()
                .unstack())
    if True not in pivot.columns or False not in pivot.columns:
        return ""

    pivot["delta"] = pivot[True] - pivot[False]
    pivot = pivot.sort_values("delta")

    fam_map = _model_to_family(llm)
    # Use family color for non-negative deltas and red for negative deltas.
    bar_colors = []
    for m, d in zip(pivot.index, pivot["delta"]):
        base = FAMILY_COLORS.get(fam_map.get(m, "Other"), GRAY)
        bar_colors.append(base if d >= 0 else RED)

    fig, ax = plt.subplots(figsize=(10, max(4, len(pivot) * 0.36)))
    bars = ax.barh(pivot.index, pivot["delta"], color=bar_colors,
                   edgecolor="white", linewidth=0.4)
    for bar, v in zip(bars, pivot["delta"]):
        offset = 0.005 if v >= 0 else -0.005
        ha = "left" if v >= 0 else "right"
        ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                f"{v:+.3f}", va="center", ha=ha, fontsize=8, color="#495057")

    ax.axvline(0, color="#495057", linewidth=1)
    ax.tick_params(axis="y", labelsize=8)
    ax.set_xlabel("Δ Match Score  (Doubled − Single)")
    ax.set_title("Consistency Delta — Family color for non-negative values, red for negative")
    _family_legend(ax, _families_present(llm, list(pivot.index)))
    fig.tight_layout()
    return _save(fig, out / "11_consistency_delta.png")


def plot_guided_vs_unguided(df: pd.DataFrame, out: Path) -> str:
    """Side-by-side: match_score guided vs unguided per model + JSON repair rate panel."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["guided"].nunique() < 2:
        return ""

    pivot = (llm.groupby(["model_short", "guided"])["match_score"]
                .mean()
                .unstack())
    if True not in pivot.columns or False not in pivot.columns:
        return ""

    pivot.columns = ["Unguided" if c is False else "Guided" for c in pivot.columns]
    pivot = pivot.sort_values("Guided", ascending=False).reset_index()

    # Repair rate: 1 - clean_json_rate, computed per model on UNGUIDED runs only
    unguided = llm[~llm["guided"]]
    if not unguided.empty:
        # Deduplicate to one row per run before computing repair rate
        run_level = unguided.drop_duplicates("run_id")
        repair = (1.0 - run_level.groupby("model_short")["raw_clean_json"].mean()
                ).rename("repair_rate")
    else:
        repair = pd.Series(dtype=float, name="repair_rate")

    fig, axes = plt.subplots(1, 2, figsize=(14, 5),
                             gridspec_kw={"width_ratios": [1.6, 1]})

    # Left: guided vs unguided match_score
    ax = axes[0]
    x = np.arange(len(pivot))
    w = 0.35
    b1 = ax.bar(x - w / 2, pivot["Unguided"], w, label="Unguided",
                color=PURPLE, edgecolor="white")
    b2 = ax.bar(x + w / 2, pivot["Guided"],   w, label="Guided",
                color=TEAL,   edgecolor="white")
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            if not np.isnan(h):
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01,
                        f"{h:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(pivot["model_short"], rotation=30, ha="right")
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Mean Match Score")
    ax.set_title("Guided vs Unguided Decoding")
    ax.legend()

    # Right: JSON repair rate (unguided only)
    ax2 = axes[1]
    if not repair.empty:
        repair = repair.sort_values(ascending=True)
        ax2.barh(repair.index, repair.values, color=ORANGE,
                 edgecolor="white", linewidth=0.4)
        for i, v in enumerate(repair.values):
            ax2.text(v + 0.01, i, f"{v:.0%}", va="center", fontsize=8,
                     color="#495057")
        ax2.set_xlim(0, 1.05)
        ax2.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax2.set_xlabel("Fraction of unguided runs requiring JSON repair")
        ax2.set_title("JSON Repair Rate (Unguided)")
    else:
        ax2.text(0.5, 0.5, "No unguided runs",
                 ha="center", va="center", transform=ax2.transAxes,
                 color=GRAY)
        ax2.set_axis_off()

    fig.tight_layout()
    return _save(fig, out / "12_guided_vs_unguided.png")


def plot_creativity_penalty(df: pd.DataFrame, out: Path) -> str:
    """Per-model field accuracy (vendor/product) split by guided vs unguided.
    Compares whether regex constraints affect field-level correctness even when
    match_score does not move.
    """
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["guided"].nunique() < 2:
        return ""

    agg = (llm.groupby(["model_short", "guided"])
              .agg(vendor=("vendor_correct", "mean"),
                   product=("product_correct", "mean"))
              .reset_index())
    if agg.empty:
        return ""

    models = sorted(agg["model_short"].unique())
    x = np.arange(len(models))
    w = 0.20

    fig, ax = plt.subplots(figsize=(max(8, len(models) * 1.7), 5))

    def _vals(field, guided):
        s = (agg[agg["guided"] == guided]
             .set_index("model_short")[field]
             .reindex(models))
        return s.values

    ax.bar(x - 1.5 * w, _vals("vendor",  False), w,
           label="Vendor — Unguided",  color=BLUE)
    ax.bar(x - 0.5 * w, _vals("vendor",  True),  w,
           label="Vendor — Guided",    color=NAVY)
    ax.bar(x + 0.5 * w, _vals("product", False), w,
           label="Product — Unguided", color=ORANGE)
    ax.bar(x + 1.5 * w, _vals("product", True),  w,
           label="Product — Guided",   color=RED)

    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=30, ha="right")
    ax.set_ylim(0, 1.1)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_ylabel("Field Accuracy")
    ax.set_title("Field Accuracy by Guided/Unguided Decoding")
    ax.legend(fontsize=8, ncol=2, loc="upper right")
    fig.tight_layout()
    return _save(fig, out / "13_creativity_penalty.png")


def plot_temperature_sensitivity(df: pd.DataFrame, out: Path) -> str:
    """Score variance (stddev) vs temperature, faceted/lined by model."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["temperature"].nunique() < 2:
        return ""

    # Group by (model, temperature, scan_id, prompt_name) so each group is the
    # set of trials sharing all conditions. Stddev across that group is
    # the stochastic variance attributable to seed/sampling.
    grp = (llm.groupby(["model_short", "temperature", "scan_id", "prompt_name"])
              ["match_score"]
              .agg(["std", "count"])
              .reset_index())
    grp = grp[grp["count"] >= 2].dropna(subset=["std"])
    if grp.empty:
        return ""

    summary = (grp.groupby(["model_short", "temperature"])["std"]
                  .mean()
                  .reset_index())

    models  = sorted(summary["model_short"].unique())
    mcolors = _model_colors(models)

    fig, ax = plt.subplots(figsize=(8, 5))
    for m in models:
        sub = (summary[summary["model_short"] == m]
               .sort_values("temperature"))
        ax.plot(sub["temperature"], sub["std"], marker="o",
                label=m, color=mcolors[m], linewidth=2)
    ax.set_xlabel("Temperature")
    ax.set_ylabel("Mean σ(match_score)  across repeated trials")
    ax.set_title("Sampling Sensitivity — Score Variance vs Temperature")
    ax.legend(fontsize=8, loc="best")
    fig.tight_layout()
    return _save(fig, out / "14_temperature_sensitivity.png")


def plot_accuracy_funnel(df: pd.DataFrame, out: Path) -> str:
    """CPE hierarchy drop-off per model: part → vendor → product → version."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty:
        return ""

    fields = ["part_correct", "vendor_correct", "product_correct", "version_correct"]
    labels = ["Part", "Vendor", "Product", "Version"]

    agg = (llm.groupby("model_short")[fields]
              .mean()
              .sort_values("vendor_correct", ascending=False))

    models  = agg.index.tolist()
    mcolors = _model_colors(models)

    fig, ax = plt.subplots(figsize=(8, 5))
    for m in models:
        ax.plot(labels, agg.loc[m, fields].values,
                marker="o", linewidth=2, label=m, color=mcolors[m])
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_ylabel("Accuracy")
    ax.set_title("Accuracy Funnel — CPE Hierarchy Drop-off")
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    return _save(fig, out / "15_accuracy_funnel.png")


def plot_hallucination_index(df: pd.DataFrame, out: Path) -> str:
    """Two-panel: vendor-only hallucination rate (vendor right, product invented),
    plus overall hallucination rate (CPE emitted but match_score=0 and vendor=0)."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty:
        return ""

    has_pred = llm["predicted_cpe"].fillna("").astype(bool)
    vendor_only_invent = (
        has_pred
        & (llm["vendor_correct"] == 1)
        & (llm["product_correct"] == 0)
    )
    by_model = (
        pd.DataFrame({
            "model_short":         llm["model_short"],
            "vendor_only_invent":  vendor_only_invent.astype(int),
            "is_hallucination":    llm["is_hallucination"],
        })
        .groupby("model_short")
        .mean()
    )
    # Order by family-mean of total hallucination, ascending (best=lowest at top)
    halluc_by_model = by_model["is_hallucination"]
    fam_for_models = llm.drop_duplicates("model_short").set_index("model_short")["model_family"]
    fam_score = (halluc_by_model.groupby(fam_for_models).mean()
                 .sort_values(ascending=False))
    order = []
    for fam in fam_score.index:
        models = fam_for_models[fam_for_models == fam].index
        sub = halluc_by_model.loc[halluc_by_model.index.intersection(models)]
        order.extend(sub.sort_values(ascending=False).index.tolist())
    by_model = by_model.reindex(order)

    fam_map = _model_to_family(llm)

    fig, ax = plt.subplots(figsize=(10, max(4, len(by_model) * 0.36)))
    y = np.arange(len(by_model))
    h = 0.4
    # Total hallucination: family color
    fam_colors = _bar_colors_by_family(by_model.index, fam_map)
    ax.barh(y - h / 2, by_model["is_hallucination"], h,
            label="Total hallucination (CPE, vendor wrong, score=0)",
            color=fam_colors, edgecolor="white")
    # Vendor-right-product-invented: hatch overlay for visual distinction
    ax.barh(y + h / 2, by_model["vendor_only_invent"], h,
            label="Vendor right, product invented",
            color=fam_colors, edgecolor="white",
            hatch="///", alpha=0.55)
    ax.set_yticks(y)
    ax.set_yticklabels(by_model.index, fontsize=8)
    # Color y-tick labels by family
    for tick, model in zip(ax.get_yticklabels(), by_model.index):
        tick.set_color(FAMILY_COLORS.get(fam_map.get(model, "Other"), "#212529"))
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_xlabel("Rate (fraction of predictions)")
    ax.set_title("Hallucination Index by Model (solid = total, hatched = vendor-only invent)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    return _save(fig, out / "16_hallucination_index.png")


def plot_payload_vs_score(df: pd.DataFrame, out: Path) -> str:
    """Scatter: payload character count vs match_score, with per-model trend lines."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["payload_chars"].nunique() < 3:
        return ""

    models  = sorted(llm["model_short"].unique())
    mcolors = _model_colors(models)

    fig, ax = plt.subplots(figsize=(10, 5))
    for m in models:
        sub = llm[llm["model_short"] == m]
        ax.scatter(sub["payload_chars"], sub["match_score"],
                   s=12, alpha=0.25, color=mcolors[m])
        # Trend line (linear fit) for visual signal
        if len(sub) >= 5 and sub["payload_chars"].std() > 0:
            coef = np.polyfit(sub["payload_chars"], sub["match_score"], 1)
            xs = np.linspace(sub["payload_chars"].min(),
                             sub["payload_chars"].max(), 50)
            ax.plot(xs, np.polyval(coef, xs),
                    color=mcolors[m], linewidth=2, label=m)
    ax.set_xlabel("Payload size (characters)")
    ax.set_ylabel("Match Score")
    ax.set_title("Payload Size vs Match Score")
    ax.legend(fontsize=8, loc="upper right", ncol=2)
    fig.tight_layout()
    return _save(fig, out / "17_payload_vs_score.png")


def plot_intensity_performance(df: pd.DataFrame, out: Path) -> str:
    """Mean match_score by scan intensity, lined per model."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    llm = llm[llm["intensity"].notna()]
    if llm.empty or llm["intensity"].nunique() < 2:
        return ""

    summary = (llm.groupby(["model_short", "intensity"])["match_score"]
                  .mean()
                  .reset_index())

    models  = sorted(summary["model_short"].unique())
    mcolors = _model_colors(models)

    fig, ax = plt.subplots(figsize=(9, 5))
    for m in models:
        sub = (summary[summary["model_short"] == m]
               .sort_values("intensity"))
        ax.plot(sub["intensity"], sub["match_score"],
                marker="o", linewidth=2, label=m, color=mcolors[m])
    ax.set_xlabel("Scan Intensity (parsed from scan_name prefix)")
    ax.set_ylabel("Mean Match Score")
    ax.set_ylim(0, 1.05)
    ax.set_title("Scan Intensity vs Accuracy")
    ax.legend(fontsize=8, loc="best", ncol=2)
    fig.tight_layout()
    return _save(fig, out / "18_intensity_performance.png")


def plot_vendor_bias(df: pd.DataFrame, out: Path) -> str:
    """Heatmap: manufacturer × model → mean match_score. Specialists vs generalists."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["manufacturer"].nunique() < 2:
        return ""

    pivot = (llm.groupby(["manufacturer", "model_short"])["match_score"]
                .mean()
                .unstack())

    model_order  = pivot.mean().sort_values(ascending=False).index.tolist()
    vendor_order = pivot.mean(axis=1).sort_values(ascending=False).index.tolist()
    pivot = pivot.loc[vendor_order, model_order]

    fig_h = max(5, len(pivot) * 0.45)
    fig_w = max(8, len(pivot.columns) * 1.3)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    sns.heatmap(pivot, annot=True, fmt=".2f", cmap="RdYlGn",
                vmin=0, vmax=1, linewidths=0.5, linecolor="white",
                mask=pivot.isnull(), ax=ax,
                annot_kws={"size": 8},
                cbar_kws={"label": "Mean Match Score", "shrink": 0.8})
    ax.set_title("Vendor Bias — Manufacturer × Model")
    ax.set_xlabel("Model")
    ax.set_ylabel("Manufacturer")
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    fig.tight_layout()
    return _save(fig, out / "19_vendor_bias.png")


def plot_baseline_lift(df: pd.DataFrame, out: Path) -> str:
    """Per-model mean lift over the nmap_baseline (computed per scan)."""
    llm = df[(df["prompt_name"] != "nmap_baseline")
             & df["baseline_lift"].notna()]
    if llm.empty:
        return ""

    agg = (llm.groupby("model_short")["baseline_lift"]
              .mean()
              .sort_values())

    fam_map = _model_to_family(llm)
    # Use family color for positive lift and red for negative lift.
    bar_colors = []
    for m, v in zip(agg.index, agg.values):
        base = FAMILY_COLORS.get(fam_map.get(m, "Other"), GRAY)
        bar_colors.append(base if v > 0 else (GRAY if v == 0 else RED))

    fig, ax = plt.subplots(figsize=(10, max(4, len(agg) * 0.36)))
    bars = ax.barh(agg.index, agg.values, color=bar_colors, edgecolor="white")
    for bar, v in zip(bars, agg.values):
        offset = 0.005 if v >= 0 else -0.005
        ha = "left" if v >= 0 else "right"
        ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                f"{v:+.3f}", va="center", ha=ha, fontsize=8, color="#495057")
    ax.axvline(0, color="#495057", linewidth=1)
    ax.tick_params(axis="y", labelsize=8)
    ax.set_xlabel("Mean Match-Score Lift over nmap baseline (per scan)")
    ax.set_title("Baseline Lift over nmap Baseline (red = negative lift)")
    _family_legend(ax, _families_present(llm, list(agg.index)))
    fig.tight_layout()
    return _save(fig, out / "20_baseline_lift.png")


# ── New association plots ─────────────────────────────────────────────────────

def plot_family_summary(df: pd.DataFrame, out: Path) -> str:
    """Box + strip per family — compresses 27 models into ~10 family groups,
    each strip dot is one model's mean score so within-family spread stays visible."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["model_family"].nunique() < 2:
        return ""

    per_model = (llm.groupby(["model_family", "model_short"])["match_score"]
                    .mean()
                    .reset_index())
    fam_order = (per_model.groupby("model_family")["match_score"]
                          .mean()
                          .sort_values(ascending=False)
                          .index.tolist())
    palette = {f: FAMILY_COLORS.get(f, GRAY) for f in fam_order}

    fig, ax = plt.subplots(figsize=(max(8, len(fam_order) * 1.1), 5))
    sns.boxplot(data=per_model, x="model_family", y="match_score",
                order=fam_order, hue="model_family", palette=palette,
                ax=ax, width=0.55, linewidth=1.0, fliersize=0,
                legend=False)
    sns.stripplot(data=per_model, x="model_family", y="match_score",
                  order=fam_order, hue="model_family", palette=palette,
                  ax=ax, size=7, alpha=0.85, edgecolor="white", linewidth=0.7,
                  jitter=0.18, legend=False)

    # Annotate sample size under each family label
    counts = per_model.groupby("model_family")["model_short"].nunique()
    for i, fam in enumerate(fam_order):
        ax.text(i, -0.06, f"n={counts.get(fam, 0)}",
                ha="center", va="top", fontsize=8, color="#6c757d",
                transform=ax.get_xaxis_transform())

    ax.set_ylim(-0.05, 1.05)
    ax.set_xlabel("")
    ax.set_ylabel("Mean Match Score (per model)")
    ax.set_title("Model Family Summary — boxes show family spread, dots are individual models")
    fig.tight_layout()
    return _save(fig, out / "21_family_summary.png")


def plot_metric_correlation(df: pd.DataFrame, out: Path) -> str:
    """Heatmap of correlation between scoring metrics."""
    cols = ["match_score", "exact_match", "vendor_correct", "product_correct",
            "version_correct", "cve_valid", "is_hallucination",
            "raw_clean_json", "payload_chars"]
    cols = [c for c in cols if c in df.columns]
    sub = df[cols].copy()
    # Cast bool-ish to numeric
    for c in cols:
        sub[c] = pd.to_numeric(sub[c], errors="coerce")
    sub = sub.dropna()
    if sub.empty or sub.shape[1] < 2:
        return ""

    corr = sub.corr(method="pearson")

    pretty = {
        "match_score":      "match_score",
        "exact_match":      "exact_match",
        "vendor_correct":   "vendor",
        "product_correct":  "product",
        "version_correct":  "version",
        "cve_valid":        "cve_valid",
        "is_hallucination": "halluc.",
        "raw_clean_json":   "clean_json",
        "payload_chars":    "payload_size",
    }
    corr.index = [pretty.get(c, c) for c in corr.index]
    corr.columns = [pretty.get(c, c) for c in corr.columns]

    fig, ax = plt.subplots(figsize=(8, 7))
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="RdBu_r",
                vmin=-1, vmax=1, linewidths=0.5, linecolor="white",
                square=True, ax=ax, annot_kws={"size": 9},
                cbar_kws={"label": "Pearson r", "shrink": 0.8})
    ax.set_title("Metric Correlation Matrix — what moves together")
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    fig.tight_layout()
    return _save(fig, out / "22_metric_correlation.png")


_LABEL_RE_ORG    = re.compile(r"^[^/]+/")              # strip "meta-llama/" etc.
_LABEL_RE_INSTR  = re.compile(r"-(?:Instruct|instruct|chat|it)$")
_LABEL_RE_CLOUD  = re.compile(r":cloud$")
_LABEL_RE_DATE   = re.compile(r"-\d{4}-\d{2}-\d{2}$")  # OpenAI date suffixes


def _short_label(model_short: str) -> str:
    """Compact display label for scatter annotations."""
    s = model_short
    s = _LABEL_RE_ORG.sub("", s)
    s = _LABEL_RE_INSTR.sub("", s)
    s = _LABEL_RE_CLOUD.sub("", s)
    s = _LABEL_RE_DATE.sub("", s)
    if len(s) > 24:
        s = s[:22] + "…"
    return s


def plot_size_scaling(df: pd.DataFrame, out: Path) -> str:
    """Parameter count vs mean match score per model.

    Two-panel layout:
      • Left panel: log-x scatter of known-size models against mean match score,
        colored by family. MoE models are drawn with two markers — a small solid
        marker at `active_b` (active parameters) and a faded ring at `total_b`
        (total parameters) connected by a thin line. A least-squares log-fit
        is drawn through the active-size points.
      • Right panel: a strip plot of frontier API models whose parameter counts
        are proprietary/undisclosed, plotted at their mean match score so they
        remain visible in the same view rather than relegated to a text legend.
    """
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty:
        return ""

    per_model = (llm.groupby(["model_short", "model_family"])
                    .agg(score=("match_score", "mean"),
                         size=("model_size_b", "first"),
                         active=("model_active_size_b", "first"))
                    .reset_index())
    sized   = per_model[per_model["size"].notna()].copy()
    unsized = per_model[per_model["size"].isna()].copy()
    if sized.empty:
        return ""

    sized["active"] = sized["active"].fillna(sized["size"])
    sized["is_moe"] = sized["active"] < sized["size"]

    has_unsized = not unsized.empty
    if has_unsized:
        fig, (ax, ax_frontier) = plt.subplots(
            1, 2, figsize=(13, 7),
            gridspec_kw={"width_ratios": [4, 1], "wspace": 0.05},
            sharey=True,
            constrained_layout=True,
        )
    else:
        fig, ax = plt.subplots(figsize=(11, 7), constrained_layout=True)
        ax_frontier = None

    # ── Left: sized models ────────────────────────────────────────────────
    for fam, sub in sized.groupby("model_family"):
        color = FAMILY_COLORS.get(fam, GRAY)
        # MoE: line from active to total, faded ring at total
        moe = sub[sub["is_moe"]]
        for _, row in moe.iterrows():
            ax.plot([row["active"], row["size"]], [row["score"], row["score"]],
                    color=color, linewidth=1.0, alpha=0.55, zorder=2)
            ax.scatter(row["size"], row["score"], s=130,
                       facecolors="none", edgecolors=color, linewidth=1.5,
                       alpha=0.6, zorder=2)
        # Primary marker at active size for every model
        ax.scatter(sub["active"], sub["score"], s=110, color=color,
                   edgecolor="white", linewidth=1.2, label=fam, zorder=3)

    # Labels: alternate above/below by score-sorted index so collisions are
    # less aggressive; use short labels so they fit.
    ordered = sized.sort_values(["active", "score"]).reset_index(drop=True)
    for i, row in ordered.iterrows():
        offset_y = 9 if (i % 2 == 0) else -11
        ax.annotate(_short_label(row["model_short"]),
                    (row["active"], row["score"]),
                    xytext=(5, offset_y), textcoords="offset points",
                    fontsize=6, color="#495057", alpha=0.85, zorder=4)

    # Log-fit trend line through active sizes
    if len(sized) >= 3 and sized["active"].nunique() >= 2:
        log_x = np.log10(sized["active"].values)
        coef = np.polyfit(log_x, sized["score"].values, 1)
        xs = np.logspace(np.log10(sized["active"].min()),
                         np.log10(sized["active"].max()), 50)
        ax.plot(xs, np.polyval(coef, np.log10(xs)),
                color="#495057", linestyle="--", linewidth=1.2,
                label=f"log-fit (slope={coef[0]:+.3f})", zorder=1)

    ax.set_xscale("log")
    ax.set_xlabel("Parameters (B, log scale; active for MoE)")
    ax.set_ylabel("Mean Match Score")
    ax.set_ylim(0, 1.05)
    ax.set_title("Parameter Count vs CPE Match Score (open-weight)")
    ax.grid(True, which="both", axis="x", alpha=0.25, linestyle=":", zorder=0)
    ax.grid(True, which="major", axis="y", alpha=0.25, linestyle=":", zorder=0)

    # ── Right: frontier (size-unknown) models ─────────────────────────────
    if ax_frontier is not None:
        fam_groups = list(unsized.groupby("model_family"))
        xs_by_fam = {fam: i for i, (fam, _) in enumerate(fam_groups)}
        for fam, sub in fam_groups:
            color = FAMILY_COLORS.get(fam, GRAY)
            sub_sorted = sub.sort_values("score").reset_index(drop=True)
            xs = [xs_by_fam[fam] + (j - (len(sub_sorted) - 1) / 2) * 0.22
                  for j in range(len(sub_sorted))]
            ax_frontier.scatter(xs, sub_sorted["score"], s=110, color=color,
                                edgecolor="white", linewidth=1.2, zorder=3)
            for x, (_, row) in zip(xs, sub_sorted.iterrows()):
                ax_frontier.annotate(_short_label(row["model_short"]),
                                     (x, row["score"]),
                                     xytext=(7, 0), textcoords="offset points",
                                     fontsize=6, color="#495057",
                                     va="center", zorder=4)
        ax_frontier.set_xticks(list(xs_by_fam.values()))
        ax_frontier.set_xticklabels(list(xs_by_fam.keys()), fontsize=8)
        ax_frontier.set_xlim(-0.7, max(xs_by_fam.values()) + 0.7)
        ax_frontier.set_title("Frontier\n(size undisclosed)", fontsize=10)
        ax_frontier.grid(True, which="major", axis="y", alpha=0.25,
                         linestyle=":", zorder=0)
        ax_frontier.tick_params(axis="y", labelleft=False)
        for spine in ("top", "right"):
            ax_frontier.spines[spine].set_visible(False)

    ax.legend(fontsize=8, loc="lower right", ncol=2)
    fig.suptitle("Scaling — Parameter Count vs CPE Match Score",
                 fontsize=13, y=1.01)
    return _save(fig, out / "23_size_scaling.png")


def plot_hallucination_drivers(df: pd.DataFrame, out: Path) -> str:
    """2×2: hallucination rate by guided, by doubled, by temperature, by payload size."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty:
        return ""

    fig, axes = plt.subplots(2, 2, figsize=(13, 9))
    fam_order = [f for f in FAMILY_ORDER if f in llm["model_family"].unique()
                 and f not in ("Baseline",)]

    # Top-left: by guided
    ax = axes[0][0]
    if llm["guided"].nunique() >= 2:
        agg = (llm.groupby(["model_family", "guided"])["is_hallucination"]
                  .mean()
                  .unstack())
        agg = agg.reindex(fam_order)
        x = np.arange(len(agg))
        w = 0.38
        ax.bar(x - w / 2, agg.get(False, pd.Series(np.nan, index=agg.index)).values,
               w, label="Unguided", color=PURPLE, edgecolor="white")
        ax.bar(x + w / 2, agg.get(True,  pd.Series(np.nan, index=agg.index)).values,
               w, label="Guided",   color=TEAL,   edgecolor="white")
        ax.set_xticks(x)
        ax.set_xticklabels(agg.index, rotation=20, ha="right", fontsize=8)
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.set_ylabel("Hallucination rate")
        ax.set_title("Hallucination by Guided/Unguided (per family)")
        ax.legend(fontsize=8)
    else:
        ax.text(0.5, 0.5, "Only one guided mode present",
                ha="center", va="center", transform=ax.transAxes, color=GRAY)
        ax.set_axis_off()

    # Top-right: by doubled
    ax = axes[0][1]
    if llm["doubled"].nunique() >= 2:
        agg = (llm.groupby(["model_family", "doubled"])["is_hallucination"]
                  .mean()
                  .unstack())
        agg = agg.reindex(fam_order)
        x = np.arange(len(agg))
        w = 0.38
        ax.bar(x - w / 2, agg.get(False, pd.Series(np.nan, index=agg.index)).values,
               w, label="Single",  color=BLUE,   edgecolor="white")
        ax.bar(x + w / 2, agg.get(True,  pd.Series(np.nan, index=agg.index)).values,
               w, label="Doubled", color=ORANGE, edgecolor="white")
        ax.set_xticks(x)
        ax.set_xticklabels(agg.index, rotation=20, ha="right", fontsize=8)
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.set_ylabel("Hallucination rate")
        ax.set_title("Hallucination by Doubled/Single (per family)")
        ax.legend(fontsize=8)
    else:
        ax.text(0.5, 0.5, "Only one doubling mode present",
                ha="center", va="center", transform=ax.transAxes, color=GRAY)
        ax.set_axis_off()

    # Bottom-left: by temperature (line per family)
    ax = axes[1][0]
    if llm["temperature"].nunique() >= 2:
        agg = (llm.groupby(["model_family", "temperature"])["is_hallucination"]
                  .mean()
                  .reset_index())
        for fam in fam_order:
            sub = agg[agg["model_family"] == fam].sort_values("temperature")
            if len(sub) < 2:
                continue
            ax.plot(sub["temperature"], sub["is_hallucination"],
                    marker="o", linewidth=2, color=FAMILY_COLORS.get(fam, GRAY),
                    label=fam)
        ax.set_xlabel("Temperature")
        ax.set_ylabel("Hallucination rate")
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.set_title("Hallucination vs Temperature")
        ax.legend(fontsize=7, ncol=2, loc="best")
    else:
        ax.text(0.5, 0.5, "Only one temperature value",
                ha="center", va="center", transform=ax.transAxes, color=GRAY)
        ax.set_axis_off()

    # Bottom-right: by payload size (binned)
    ax = axes[1][1]
    if llm["payload_chars"].nunique() >= 4:
        bins = pd.qcut(llm["payload_chars"], q=5, duplicates="drop")
        binned = (llm.assign(_bin=bins)
                     .groupby(["model_family", "_bin"], observed=True)["is_hallucination"]
                     .mean()
                     .reset_index())
        bin_labels = [f"{int(b.left):,}–{int(b.right):,}"
                      for b in binned["_bin"].cat.categories]
        for fam in fam_order:
            sub = binned[binned["model_family"] == fam]
            if sub.empty:
                continue
            ax.plot(range(len(bin_labels)),
                    sub.set_index("_bin").reindex(binned["_bin"].cat.categories)["is_hallucination"].values,
                    marker="o", linewidth=2, color=FAMILY_COLORS.get(fam, GRAY),
                    label=fam)
        ax.set_xticks(range(len(bin_labels)))
        ax.set_xticklabels(bin_labels, rotation=20, ha="right", fontsize=8)
        ax.set_xlabel("Payload size (chars, quintile)")
        ax.set_ylabel("Hallucination rate")
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.set_title("Hallucination vs Payload Size")
        ax.legend(fontsize=7, ncol=2, loc="best")
    else:
        ax.text(0.5, 0.5, "Not enough payload variation",
                ha="center", va="center", transform=ax.transAxes, color=GRAY)
        ax.set_axis_off()

    fig.suptitle("Hallucination Drivers — what makes models invent CPEs",
                 fontsize=14, fontweight="bold", y=1.00)
    fig.tight_layout()
    return _save(fig, out / "24_hallucination_drivers.png")


def plot_cloud_vs_local(df: pd.DataFrame, out: Path) -> str:
    """Per-family comparison of cloud-hosted vs local models."""
    llm = df[df["prompt_name"] != "nmap_baseline"]
    if llm.empty or llm["is_cloud"].nunique() < 2:
        return ""

    fam_order = [f for f in FAMILY_ORDER if f in llm["model_family"].unique()
                 and f not in ("Baseline",)]
    agg = (llm.groupby(["model_family", "is_cloud"])
               .agg(score=("match_score", "mean"),
                    halluc=("is_hallucination", "mean"),
                    n_models=("model_short", "nunique"))
               .reset_index())

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    for ax, metric, title, fmt in [
        (axes[0], "score",  "Mean Match Score",       lambda v: f"{v:.3f}"),
        (axes[1], "halluc", "Hallucination Rate",     lambda v: f"{v:.0%}"),
    ]:
        x = np.arange(len(fam_order))
        w = 0.38
        local_vals = []
        cloud_vals = []
        local_n = []
        cloud_n = []
        for fam in fam_order:
            sub = agg[agg["model_family"] == fam]
            l = sub[sub["is_cloud"] == False]
            c = sub[sub["is_cloud"] == True]
            local_vals.append(l[metric].iloc[0] if not l.empty else np.nan)
            cloud_vals.append(c[metric].iloc[0] if not c.empty else np.nan)
            local_n.append(int(l["n_models"].iloc[0]) if not l.empty else 0)
            cloud_n.append(int(c["n_models"].iloc[0]) if not c.empty else 0)

        b1 = ax.bar(x - w / 2, local_vals, w, label="Local",
                    color=BLUE,   edgecolor="white")
        b2 = ax.bar(x + w / 2, cloud_vals, w, label="Cloud",
                    color=ORANGE, edgecolor="white")

        for bars, ns, vals in ((b1, local_n, local_vals),
                                (b2, cloud_n, cloud_vals)):
            for bar, n, v in zip(bars, ns, vals):
                if np.isnan(v):
                    continue
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.005,
                        f"{fmt(v)}\n(n={n})", ha="center", va="bottom",
                        fontsize=7.5, color="#495057")

        ax.set_xticks(x)
        ax.set_xticklabels(fam_order, rotation=20, ha="right", fontsize=8)
        ax.set_title(title)
        ax.set_ylabel(title)
        if metric == "halluc":
            ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.legend(fontsize=8)

    fig.suptitle("Cloud vs Local — Per-Family Comparison",
                 fontsize=14, fontweight="bold", y=1.02)
    fig.tight_layout()
    return _save(fig, out / "25_cloud_vs_local.png")


# ── Summary statistics ─────────────────────────────────────────────────────────

def compute_summary(df: pd.DataFrame) -> dict:
    best_model = (df.groupby("model_short")["match_score"]
                    .mean()
                    .sort_values(ascending=False)
                    .index[0])
    n_empty = (df.groupby("run_id")["match_score"]
                 .sum()
                 .eq(0)
                 .sum())

    llm = df[df["prompt_name"] != "nmap_baseline"]
    halluc_rate = float(llm["is_hallucination"].mean()) if not llm.empty else 0.0

    lift_series = llm["baseline_lift"].dropna()
    mean_lift = float(lift_series.mean()) if not lift_series.empty else float("nan")

    # Repair rate computed at the run level, unguided only, not per-prediction
    unguided_runs = (llm[~llm["guided"]]
                     .drop_duplicates("run_id"))
    if not unguided_runs.empty:
        repair_rate = float(1.0 - unguided_runs["raw_clean_json"].mean())
    else:
        repair_rate = float("nan")

    return {
        "n_models":     df["model_short"].nunique(),
        "n_devices":    df["device_code"].nunique(),
        "n_runs":       df["run_id"].nunique(),
        "n_preds":      int(df["predicted_cpe"].notna().sum()),
        "n_empty_runs": int(n_empty),
        "overall_score": float(df["match_score"].mean()),
        "exact_rate":    float(df["exact_match"].mean()),
        "best_model":    best_model,
        "halluc_rate":   halluc_rate,
        "mean_lift":     mean_lift,
        "repair_rate":   repair_rate,
    }


def compute_model_table(df: pd.DataFrame) -> pd.DataFrame:
    llm_only_cols = (df[df["prompt_name"] != "nmap_baseline"]
                     .groupby("model_short")
                     .agg(Hallucination_Rate=("is_hallucination", "mean"),
                          Baseline_Lift=("baseline_lift", "mean")))

    base = (df.groupby("model_short")
              .agg(
                  Runs=("run_id",         "nunique"),
                  Predictions=("match_score",   "count"),
                  Mean_Score=("match_score",     "mean"),
                  Exact_Rate=("exact_match",     "mean"),
                  Vendor_Acc=("vendor_correct",  "mean"),
                  Product_Acc=("product_correct","mean"),
                  Version_Acc=("version_correct","mean"),
                  CVE_Valid=("cve_valid",         "mean"),
              ))

    out = base.join(llm_only_cols, how="left")
    return (out
            .sort_values("Mean_Score", ascending=False)
            .reset_index()
            .rename(columns={"model_short": "Model"}))


# ── HTML report ────────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg:#f0f2f5; --card:#ffffff; --border:#dee2e6;
  --text:#212529; --muted:#6c757d;
  --accent:#4361ee; --green:#2dc653; --orange:#f4a261;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}
header{background:linear-gradient(135deg,#1d3557,#4361ee);color:white;padding:2.2rem 3rem;}
header h1{font-size:2rem;font-weight:700;letter-spacing:-0.02em;}
header .meta{opacity:0.8;margin-top:.4rem;font-size:.95rem;}
main{max-width:1400px;margin:0 auto;padding:2rem;}
h2{font-size:1.2rem;font-weight:700;margin:2.5rem 0 1rem;padding-bottom:.4rem;
   border-bottom:2px solid var(--border);color:#1d3557;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:1rem;margin-bottom:1.5rem;}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;
           padding:1.1rem 1.3rem;box-shadow:0 1px 4px rgba(0,0,0,.05);}
.stat-card .lbl{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}
.stat-card .val{font-size:1.9rem;font-weight:700;color:var(--accent);line-height:1.2;}
.stat-card .sub{font-size:.8rem;color:var(--muted);margin-top:.2rem;}
.table-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border);
            box-shadow:0 1px 4px rgba(0,0,0,.05);margin-bottom:1.5rem;}
table{border-collapse:collapse;width:100%;font-size:.87rem;background:var(--card);}
th{background:#1d3557;color:white;padding:.6rem 1rem;text-align:left;font-weight:600;}
th:first-child{border-radius:10px 0 0 0;}
th:last-child{border-radius:0 10px 0 0;}
td{padding:.5rem 1rem;border-bottom:1px solid var(--border);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:#f1f3f5;}
.best{color:var(--green);font-weight:700;}
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(580px,1fr));gap:1.5rem;}
.chart-card{background:var(--card);border:1px solid var(--border);border-radius:10px;
            padding:1.3rem;box-shadow:0 1px 4px rgba(0,0,0,.05);}
.chart-card h3{font-size:.95rem;font-weight:600;margin-bottom:.9rem;color:#1d3557;}
.chart-card img{width:100%;height:auto;border-radius:6px;}
.chart-full{grid-column:1/-1;}
footer{text-align:center;padding:2rem;color:var(--muted);font-size:.82rem;}
"""


def _table_html(df: pd.DataFrame) -> str:
    pct = {"Exact_Rate", "Vendor_Acc", "Product_Acc", "Version_Acc",
           "CVE_Valid", "Hallucination_Rate"}
    flt = {"Mean_Score"}
    signed = {"Baseline_Lift"}

    html = "<table><thead><tr>"
    for c in df.columns:
        html += f"<th>{c.replace('_', ' ')}</th>"
    html += "</tr></thead><tbody>"

    best = df["Mean_Score"].max()
    for _, row in df.iterrows():
        html += "<tr>"
        for c in df.columns:
            v = row[c]
            cls = ' class="best"' if c == "Mean_Score" and v == best else ""
            if pd.isna(v):
                cell = "—"
            elif c in pct:
                cell = f"{v:.1%}"
            elif c in flt:
                cell = f"{v:.4f}"
            elif c in signed:
                cell = f"{v:+.3f}"
            elif isinstance(v, float):
                cell = f"{v:.3f}"
            else:
                cell = str(v)
            html += f"<td{cls}>{cell}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    return html


def _card(title: str, b64: str, full: bool = False) -> str:
    cls = "chart-card chart-full" if full else "chart-card"
    return (f'<div class="{cls}"><h3>{title}</h3>'
            f'<img src="data:image/png;base64,{b64}" alt="{title}"></div>')


def generate_report(summary: dict, model_table: pd.DataFrame,
                    plots: dict, out_dir: Path, ts: str) -> Path:
    cards = []
    spec = [
        # Performance and prompts
        ("model_comparison",       "Model Performance — Mean CPE Match Score",      True),
        ("field_accuracy",         "CPE Field Accuracy by Model",                    False),
        ("tier_breakdown",         "Match Tier Distribution by Model",               False),
        ("score_distribution",     "Score Distribution by Model (Violin)",           False),
        ("prompt_ablation",        "Prompt Ablation — Persona × Structure",          True),
        ("doubled_effect",         "Effect of Doubled Prompt Mode",                  False),
        ("device_heatmap",         "Mean Match Score — Device × Model",              True),
        ("scan_type",              "Performance by Scan Type",                       True),
        ("exact_and_cve",          "Exact Match & CVE Validity Rates",               False),
        ("trial_variance",         "Score Variance Across Trials",                   False),
        # Prompt repetition
        ("consistency_delta",      "Consistency Delta by Model",                     False),
        # Guided decoding
        ("guided_vs_unguided",     "Guided vs Unguided Decoding + JSON Repair Rate", True),
        ("creativity_penalty",     "Field Accuracy by Decoding Mode",                True),
        # Sampling
        ("temperature_sensitivity","Sampling Sensitivity — σ vs Temperature",        False),
        # Hierarchy and hallucination
        ("accuracy_funnel",        "Accuracy Funnel — CPE Hierarchy Drop-off",       False),
        ("hallucination_index",    "Hallucination Index by Model",                   True),
        # Payload and scan intensity
        ("payload_vs_score",       "Payload Size vs Match Score",                    True),
        ("intensity_performance",  "Intensity vs Accuracy",                          True),
        # Vendor bias
        ("vendor_bias",            "Vendor Bias — Manufacturer × Model",             True),
        # Baseline comparison
        ("baseline_lift",          "Baseline Lift over nmap baseline",               False),
        # Family and cross-cutting comparisons
        ("family_summary",         "Model Family Summary — boxes + per-model dots",  True),
        ("metric_correlation",     "Metric Correlation Matrix",                      False),
        ("size_scaling",           "Parameter Count vs Match Score",                 True),
        ("hallucination_drivers",  "Hallucination Drivers — guided × doubled × temp × payload", True),
        ("cloud_vs_local",         "Cloud vs Local — Per-Family Comparison",         True),
    ]
    for key, title, full in spec:
        b64 = plots.get(key, "")
        if b64:
            cards.append(_card(title, b64, full))

    # Format optional summary fields
    def _fmt_pct(v): return "—" if v is None or (isinstance(v, float) and np.isnan(v)) else f"{v:.1%}"
    def _fmt_signed(v): return "—" if v is None or (isinstance(v, float) and np.isnan(v)) else f"{v:+.3f}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LLM CPE Prediction Analysis — {ts}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>LLM CPE Prediction Analysis</h1>
  <div class="meta">Generated {ts}&nbsp;&nbsp;·&nbsp;&nbsp;{summary['n_models']} models&nbsp;&nbsp;·&nbsp;&nbsp;{summary['n_devices']} devices&nbsp;&nbsp;·&nbsp;&nbsp;{summary['n_runs']:,} runs</div>
</header>
<main>

<h2>Summary Statistics</h2>
<div class="stats-grid">
  <div class="stat-card"><div class="lbl">Models Tested</div><div class="val">{summary['n_models']}</div></div>
  <div class="stat-card"><div class="lbl">Devices</div><div class="val">{summary['n_devices']}</div></div>
  <div class="stat-card"><div class="lbl">Total Runs</div><div class="val">{summary['n_runs']:,}</div></div>
  <div class="stat-card"><div class="lbl">Total Predictions</div><div class="val">{summary['n_preds']:,}</div></div>
  <div class="stat-card"><div class="lbl">Empty Runs</div><div class="val">{summary['n_empty_runs']}</div><div class="sub">runs with no predictions</div></div>
  <div class="stat-card"><div class="lbl">Overall Match Score</div><div class="val">{summary['overall_score']:.3f}</div><div class="sub">mean across all predictions</div></div>
  <div class="stat-card"><div class="lbl">Exact Match Rate</div><div class="val">{summary['exact_rate']:.1%}</div></div>
  <div class="stat-card"><div class="lbl">Hallucination Rate</div><div class="val">{_fmt_pct(summary['halluc_rate'])}</div><div class="sub">CPE emitted, vendor wrong, score 0</div></div>
  <div class="stat-card"><div class="lbl">Mean Baseline Lift</div><div class="val">{_fmt_signed(summary['mean_lift'])}</div><div class="sub">vs nmap baseline (per scan)</div></div>
  <div class="stat-card"><div class="lbl">JSON Repair Rate</div><div class="val">{_fmt_pct(summary['repair_rate'])}</div><div class="sub">unguided runs requiring repair</div></div>
  <div class="stat-card"><div class="lbl">Best Model</div><div class="val" style="font-size:1rem;padding-top:.35rem">{summary['best_model']}</div></div>
</div>

<h2>Per-Model Results</h2>
<div class="table-wrap">{_table_html(model_table)}</div>

<h2>Charts</h2>
<div class="chart-grid">{"".join(cards)}</div>

</main>
<footer>Thesis — CPE Prediction Benchmark &nbsp;·&nbsp; {ts}</footer>
</body>
</html>"""

    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path


# ── Markdown analysis context document ────────────────────────────────────────

def _fmt_num(v, fmt=".3f"):
    """Format a scalar for the markdown context. Returns '—' for null/NaN.

    Handles format-code mismatches (e.g. "d" applied to a float that pandas
    promoted from an int column) by coercing rather than raising.
    """
    if v is None:
        return "—"
    if isinstance(v, (float, np.floating)) and (np.isnan(v) or np.isinf(v)):
        return "—"
    if isinstance(v, (bool, np.bool_)):
        return "true" if bool(v) else "false"
    if fmt == "s" or fmt.endswith("s"):
        return str(v)
    if fmt.endswith("d"):
        try:
            return format(int(v), fmt)
        except (ValueError, TypeError):
            return str(v)
    # Float-style formats (e.g. ".3f", "+.3f", ".1%")
    try:
        return format(float(v), fmt)
    except (ValueError, TypeError):
        return str(v)


def _df_to_md(df_in: pd.DataFrame, fmts: dict | None = None,
              max_rows: int | None = None) -> str:
    """Render a DataFrame as a GitHub-flavoured Markdown pipe table."""
    fmts = fmts or {}
    if max_rows is not None and len(df_in) > max_rows:
        df_in = df_in.head(max_rows)
    cols = list(df_in.columns)
    header = "| " + " | ".join(str(c) for c in cols) + " |"
    sep    = "| " + " | ".join("---" for _ in cols) + " |"
    rows   = []
    for _, r in df_in.iterrows():
        cells = []
        for c in cols:
            v = r[c]
            cells.append(_fmt_num(v, fmts.get(c, ".3f")))
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, sep] + rows)


def _series_to_md(s: pd.Series, value_name: str = "value",
                  fmt: str = ".3f", index_name: str | None = None) -> str:
    """Render a Series as a 2-column Markdown table."""
    idx_name = index_name or (s.index.name or "key")
    df_in = pd.DataFrame({idx_name: s.index, value_name: s.values})
    return _df_to_md(df_in, fmts={value_name: fmt})


def _safe_corr(values_x, values_y) -> float:
    """Pearson correlation between two array-likes, NaN if undefined."""
    x = np.asarray(values_x, dtype=float)
    y = np.asarray(values_y, dtype=float)
    mask = ~(np.isnan(x) | np.isnan(y))
    if mask.sum() < 3 or np.std(x[mask]) == 0 or np.std(y[mask]) == 0:
        return float("nan")
    return float(np.corrcoef(x[mask], y[mask])[0, 1])


def generate_llm_context_doc(df: pd.DataFrame, summary: dict,
                             model_table: pd.DataFrame,
                             out_dir: Path, ts: str) -> Path:
    """Write a Markdown context document summarising every plot, relationship,
    and underlying aggregate for downstream analysis."""

    parts: list[str] = []
    A = parts.append

    llm = df[df["prompt_name"] != "nmap_baseline"]

    # ── 1. Overview ─────────────────────────────────────────────────────────
    A(f"# LLM CPE-Prediction Benchmark — Analysis Context\n")
    A(f"_Generated {ts}._\n")
    A("This document describes the dataset, every chart in `report.html`, "
      "the relationships between metrics, and the aggregated data underlying "
      "each plot. It provides downstream analysis context without requiring "
      "another query against the raw data.\n")

    A("## 1. Dataset Summary\n")
    A(f"- Models tested: **{summary['n_models']}**")
    A(f"- Devices: **{summary['n_devices']}**")
    A(f"- Total runs: **{summary['n_runs']:,}**")
    A(f"- Total predictions (rows): **{summary['n_preds']:,}**")
    A(f"- Empty runs (no predictions emitted): **{summary['n_empty_runs']}**")
    A(f"- Overall mean match_score: **{summary['overall_score']:.3f}**")
    A(f"- Exact-match rate: **{summary['exact_rate']:.1%}**")
    halluc = summary['halluc_rate']
    A(f"- Hallucination rate: **{halluc:.1%}**" if not np.isnan(halluc) else "- Hallucination rate: —")
    lift = summary['mean_lift']
    A(f"- Mean baseline lift (LLM − nmap_baseline, per scan): "
      f"**{lift:+.3f}**" if not np.isnan(lift) else
      "- Mean baseline lift: —")
    rep = summary['repair_rate']
    A(f"- JSON repair rate (unguided runs needing repair): **{rep:.1%}**"
      if not np.isnan(rep) else "- JSON repair rate: —")
    A(f"- Best model by mean match_score: **{summary['best_model']}**\n")

    # ── 2. Schema ───────────────────────────────────────────────────────────
    A("## 2. Schema — DataFrame columns\n")
    A("Each row is one *prediction*; one model_run can emit ≥1 predictions "
      "(scored separately) or zero (empty run, recorded with all-zero score row).\n")
    A("| Column | Meaning |")
    A("| --- | --- |")
    schema = [
        ("run_id",           "Unique run identifier."),
        ("scan_id",          "Source nmap scan id."),
        ("model",            "Full model identifier (`provider/name:tag`)."),
        ("model_short",      "Display name (basename, ≤35 chars)."),
        ("model_family",     "Architecture family (Llama / Qwen / Gemma / Mistral / Phi / DeepSeek / Granite / GLM / Kimi / GPT-OSS / GPT / Claude / Gemini / SecTuned / Other / Baseline)."),
        ("model_size_b",        "Total parameter count in billions, looked up in `model_sizes.json` (regex on the model name as fallback). NaN for proprietary / undisclosed models."),
        ("model_active_size_b", "Active parameter count in billions; equals `model_size_b` for dense models, smaller for MoE. NaN when undisclosed."),
        ("is_cloud",            "True if `model` contains `:cloud`."),
        ("prompt_name",      "Prompt variant. `nmap_baseline` means *no LLM* — raw nmap baseline used as control."),
        ("persona",          "`persona` vs `neutral`, derived from prompt_name."),
        ("structured",       "`structured` vs `minimal`, derived from prompt_name."),
        ("doubled",          "Double-prompt mode (the prompt and scan payload are repeated in one user message)."),
        ("trial",            "Trial number for repeated trials of identical conditions (used to estimate sampling variance)."),
        ("temperature",      "Sampling temperature (0.0 = greedy)."),
        ("guided",           "True iff guided / structured decoding (regex-constrained output) was used."),
        ("seed",             "RNG seed if any."),
        ("scan_name",        "Scan recipe name (e.g. `01-sv-osc-top1000`)."),
        ("intensity",        "Leading integer parsed from `scan_name`; used as a coarse scan-intensity axis."),
        ("device_code",      "Device identifier."),
        ("manufacturer",     "Device manufacturer."),
        ("payload_chars",    "Length of nmap payload fed to the model (proxy for input density)."),
        ("raw_clean_json",   "True iff `raw_output` parsed as JSON without any repair (clean format compliance)."),
        ("predicted_cpe",    "The CPE string the model emitted (may be empty)."),
        ("part_correct",     "1 iff the CPE *part* (`h`/`o`/`a`) matches expected."),
        ("vendor_correct",   "1 iff vendor matches expected."),
        ("product_correct",  "1 iff product matches expected."),
        ("version_correct",  "1 iff version matches expected."),
        ("exact_match",      "1 iff `predicted_cpe` exactly equals an expected CPE string."),
        ("cve_valid",        "1 iff predicted CPE resolves to ≥1 CVE in the lookup."),
        ("match_score",      "Weighted hierarchical similarity ∈ [0, 1]; primary metric."),
        ("best_tier",        "Categorical: `exact` > `partial` > `related` > `none` (best tier achieved across expected CPEs for this prediction)."),
        ("is_hallucination", "Derived: `predicted_cpe` non-empty AND `vendor_correct=0` AND `match_score=0`."),
        ("precision_gap",    "1 − match_score (how far from exact)."),
        ("baseline_lift",    "`match_score` − mean(`nmap_baseline` match_score) for the same `scan_id`. NaN for baseline rows themselves."),
    ]
    for col, desc in schema:
        A(f"| `{col}` | {desc} |")
    A("")

    # ── 3. Per-model results table ──────────────────────────────────────────
    A("## 3. Per-Model Results\n")
    A("Aggregated over all runs and predictions for each model. "
      "`Hallucination_Rate` and `Baseline_Lift` are computed on LLM rows only "
      "(i.e. excluding `nmap_baseline`).\n")
    pct_cols = {"Exact_Rate", "Vendor_Acc", "Product_Acc", "Version_Acc",
                "CVE_Valid", "Hallucination_Rate"}
    fmts = {c: ".1%" if c in pct_cols else
               (".4f" if c == "Mean_Score" else
                ("+.3f" if c == "Baseline_Lift" else ".3f"))
            for c in model_table.columns}
    fmts["Model"] = "s"
    fmts["Runs"] = "d"
    fmts["Predictions"] = "d"
    A(_df_to_md(model_table, fmts=fmts))
    A("")

    # ── 4. Models inventory ─────────────────────────────────────────────────
    A("## 4. Model Inventory\n")
    inv = (df.drop_duplicates("model_short")
             [["model_short", "model_family", "model_size_b", "is_cloud", "model"]]
             .sort_values(["model_family", "model_short"])
             .rename(columns={"model_short": "Model",
                              "model_family": "Family",
                              "model_size_b": "Size_B",
                              "is_cloud":     "Cloud",
                              "model":        "Full_Name"}))
    A(_df_to_md(inv, fmts={"Size_B": ".1f", "Cloud": "s",
                            "Family": "s", "Model": "s", "Full_Name": "s"}))
    A("")

    # ── 5. Per-plot sections ────────────────────────────────────────────────
    A("## 5. Charts — purpose, data, and findings\n")
    A("Each subsection corresponds to a PNG in this directory and a card in "
      "`report.html`. The aggregated values needed to interpret the chart "
      "without seeing the image are reproduced inline.\n")

    # 5.1 Model comparison
    A("### 5.1 `01_model_comparison.png` — Model Performance (mean match_score)\n")
    A("**Shows.** Horizontal bar of mean `match_score` per model, ± SEM, "
      "grouped and coloured by family.\n")
    A("**Interpretation.** Compare this ranking with `nmap_baseline` to measure "
      "the additional signal from each model.\n")
    mc = (df.groupby("model_short")
            .agg(mean=("match_score", "mean"),
                 sem=("match_score", lambda x: x.std() / np.sqrt(max(len(x), 1))),
                 n=("match_score", "count"))
            .sort_values("mean", ascending=False)
            .reset_index()
            .rename(columns={"model_short": "Model"}))
    A("**Mean ± SEM (sorted desc):**")
    A(_df_to_md(mc, fmts={"Model": "s", "mean": ".4f", "sem": ".4f", "n": "d"}))
    A("")

    # 5.2 Field accuracy
    A("### 5.2 `02_field_accuracy.png` — CPE Field Accuracy by Model\n")
    A("**Shows.** Grouped bars of vendor / product / version correctness rates per model.\n")
    A("**Interpretation.** Separates vendor, product, and version accuracy to "
      "show where identification errors occur.\n")
    fa = (df.groupby("model_short")
            .agg(Vendor=("vendor_correct", "mean"),
                 Product=("product_correct", "mean"),
                 Version=("version_correct", "mean"))
            .sort_values("Vendor", ascending=False)
            .reset_index()
            .rename(columns={"model_short": "Model"}))
    A(_df_to_md(fa, fmts={"Model": "s", "Vendor": ".1%",
                           "Product": ".1%", "Version": ".1%"}))
    A("")

    # 5.3 Tier breakdown
    A("### 5.3 `03_tier_breakdown.png` — Match Tier Distribution\n")
    A("**Shows.** Stacked horizontal fractions of `best_tier` "
      "(`exact` / `partial` / `related` / `none`) per model.\n")
    A("**Interpretation.** Distinguishes models with similar means but different "
      "distributions of exact, partial, related, and unmatched predictions.\n")
    tier_pivot = (df.groupby(["model_short", "best_tier"], observed=True)
                    .size()
                    .unstack(fill_value=0)
                    .reindex(columns=TIER_ORDER, fill_value=0))
    tier_frac = tier_pivot.div(tier_pivot.sum(axis=1), axis=0).reset_index()
    tier_frac = tier_frac.rename(columns={"model_short": "Model"})
    tier_frac = tier_frac.sort_values("exact", ascending=False)
    A(_df_to_md(tier_frac, fmts={"Model": "s", "exact": ".1%",
                                  "partial": ".1%", "related": ".1%",
                                  "none": ".1%"}))
    A("")

    # 5.4 Score distribution
    A("### 5.4 `04_score_distribution.png` — Score Distribution by Model\n")
    A("**Shows.** Violin + inner box of `match_score` per model.\n")
    A("**Interpretation.** The distribution shows whether similar means represent "
      "uniform scores or a split between exact and unmatched predictions.\n")
    dist = (df.groupby("model_short")["match_score"]
              .agg(mean="mean", std="std",
                   q25=lambda x: x.quantile(0.25),
                   median="median",
                   q75=lambda x: x.quantile(0.75))
              .sort_values("mean", ascending=False)
              .reset_index()
              .rename(columns={"model_short": "Model"}))
    A(_df_to_md(dist, fmts={"Model": "s", "mean": ".3f", "std": ".3f",
                             "q25": ".3f", "median": ".3f", "q75": ".3f"}))
    A("")

    # 5.5 Prompt ablation
    A("### 5.5 `05_prompt_ablation.png` — Persona × Structure\n")
    A("**Shows.** 2×2 heatmap of mean `match_score` by `persona` and `structured`, "
      "plus per-model lines across the four prompt variants.\n")
    A("**Interpretation.** Measures the effect of persona priming and structured "
      "format requests for each model.\n")
    if not llm.empty and llm["persona"].nunique() >= 2 and llm["structured"].nunique() >= 2:
        ab = (llm.groupby(["persona", "structured"])["match_score"]
                 .mean()
                 .unstack())
        A("**Mean match_score by (persona × structure):**")
        A(_df_to_md(ab.reset_index(), fmts={"persona": "s",
                                              **{c: ".3f" for c in ab.columns}}))
    else:
        A("_Single persona/structure level — ablation skipped._")
    A("")

    # 5.6 Doubled effect
    A("### 5.6 `06_doubled_effect.png` — Doubled vs Single Prompt\n")
    A("**Shows.** Per-model bars for `doubled=False` (single) and `doubled=True` "
      "(prompt and payload repeated in one message).\n")
    A("**Interpretation.** Measures whether repeating the prompt and payload "
      "changes prediction accuracy.\n")
    if not llm.empty and llm["doubled"].nunique() >= 2:
        de = (llm.groupby(["model_short", "doubled"])["match_score"]
                .mean().unstack())
        de.columns = ["Single" if c is False else "Doubled" for c in de.columns]
        de["Δ (D−S)"] = de.get("Doubled", np.nan) - de.get("Single", np.nan)
        de = de.sort_values("Δ (D−S)", ascending=False).reset_index()\
                .rename(columns={"model_short": "Model"})
        A(_df_to_md(de, fmts={"Model": "s", "Single": ".3f",
                               "Doubled": ".3f", "Δ (D−S)": "+.3f"}))
    else:
        A("_Only one doubled mode present — skipped._")
    A("")

    # 5.7 Device heatmap
    A("### 5.7 `07_device_heatmap.png` — Device × Model\n")
    A("**Shows.** Heatmap of mean `match_score` for each (device_code, model) cell.\n")
    A("**Interpretation.** Identifies device-specific differences in model "
      "accuracy.\n")
    dh = (df.groupby(["device_code", "model_short"])["match_score"]
            .mean()
            .unstack())
    dh = dh.loc[dh.mean(axis=1).sort_values(ascending=False).index,
                dh.mean().sort_values(ascending=False).index]
    A("**Device row means (overall difficulty per device, sorted desc):**")
    A(_series_to_md(dh.mean(axis=1).sort_values(ascending=False),
                    value_name="mean_score", fmt=".3f", index_name="device_code"))
    A("\n**Model column means (overall, sorted desc):**")
    A(_series_to_md(dh.mean().sort_values(ascending=False),
                    value_name="mean_score", fmt=".3f", index_name="Model"))
    A("")

    # 5.8 Scan type
    A("### 5.8 `08_scan_type.png` — Performance by Scan Type\n")
    A("**Shows.** Grouped bars of mean `match_score` per `scan_name`, split by model.\n")
    A("**Interpretation.** Compares performance as the amount and type of scan "
      "data vary.\n")
    st = (df.groupby("scan_name")["match_score"]
            .agg(["mean", "count"])
            .sort_values("mean", ascending=False)
            .reset_index()
            .rename(columns={"scan_name": "Scan", "count": "n"}))
    A(_df_to_md(st, fmts={"Scan": "s", "mean": ".3f", "n": "d"}))
    A("")

    # 5.9 Exact + CVE
    A("### 5.9 `09_exact_and_cve.png` — Exact-Match & CVE Validity\n")
    A("**Shows.** Per-model bars of `exact_match` rate and `cve_valid` rate.\n")
    A("**Interpretation.** Exact match measures identifier agreement; CVE-validity "
      "measures whether the emitted CPE resolves in the lookup data.\n")
    ec = (df.groupby("model_short")
            .agg(Exact_Rate=("exact_match", "mean"),
                 CVE_Valid=("cve_valid", "mean"))
            .sort_values("Exact_Rate", ascending=False)
            .reset_index()
            .rename(columns={"model_short": "Model"}))
    A(_df_to_md(ec, fmts={"Model": "s", "Exact_Rate": ".1%",
                           "CVE_Valid": ".1%"}))
    A("")

    # 5.10 Trial variance
    A("### 5.10 `10_trial_variance.png` — Score Variance Across Trials\n")
    A("**Shows.** Box plot of `match_score` by `trial` (LLM rows only).\n")
    A("**Interpretation.** High variance across identical conditions indicates "
      "that more trials may be required for stable estimates.\n")
    if not llm.empty and llm["trial"].nunique() >= 2:
        tv = (llm.groupby("trial")["match_score"]
                .agg(["mean", "std", "count"])
                .reset_index()
                .rename(columns={"trial": "Trial", "count": "n"}))
        A(_df_to_md(tv, fmts={"Trial": "d", "mean": ".3f",
                               "std": ".3f", "n": "d"}))
    else:
        A("_Single trial only — skipped._")
    A("")

    # 5.11 Consistency delta
    A("### 5.11 `11_consistency_delta.png` — Consistency Delta\n")
    A("**Shows.** Per-model Δ = mean(match_score | doubled) − mean(match_score | single).\n")
    A("**Interpretation.** Positive deltas indicate higher scores with repeated "
      "input; negative deltas indicate lower scores.\n")
    if not llm.empty and llm["doubled"].nunique() >= 2:
        cd = (llm.groupby(["model_short", "doubled"])["match_score"]
                .mean().unstack())
        if True in cd.columns and False in cd.columns:
            cd["delta"] = cd[True] - cd[False]
            cd = cd.sort_values("delta", ascending=False).reset_index()\
                    .rename(columns={"model_short": "Model",
                                     False: "Single", True: "Doubled"})
            A(_df_to_md(cd, fmts={"Model": "s", "Single": ".3f",
                                   "Doubled": ".3f", "delta": "+.3f"}))
    A("")

    # 5.12 Guided vs unguided
    A("### 5.12 `12_guided_vs_unguided.png` — Guided vs Unguided + JSON Repair\n")
    A("**Shows.** Per-model match_score for guided vs unguided decoding, and "
      "a side panel of the fraction of unguided runs that required JSON repair.\n")
    A("**Interpretation.** Compares the accuracy and format-compliance effects "
      "of regex-constrained decoding. Repair rate measures raw format compliance.\n")
    if not llm.empty and llm["guided"].nunique() >= 2:
        gu = (llm.groupby(["model_short", "guided"])["match_score"]
                .mean().unstack())
        if True in gu.columns and False in gu.columns:
            gu.columns = ["Unguided" if c is False else "Guided" for c in gu.columns]
            gu["Δ (G−U)"] = gu["Guided"] - gu["Unguided"]
            gu = gu.sort_values("Guided", ascending=False).reset_index()\
                    .rename(columns={"model_short": "Model"})
            A("**Mean match_score by guided/unguided:**")
            A(_df_to_md(gu, fmts={"Model": "s", "Unguided": ".3f",
                                   "Guided": ".3f", "Δ (G−U)": "+.3f"}))
        unguided = llm[~llm["guided"]]
        if not unguided.empty:
            run_lvl = unguided.drop_duplicates("run_id")
            repair = (1.0 - run_lvl.groupby("model_short")["raw_clean_json"].mean())\
                        .sort_values(ascending=False)
            A("\n**JSON repair rate (unguided runs requiring repair, sorted desc):**")
            A(_series_to_md(repair, value_name="repair_rate", fmt=".1%",
                            index_name="Model"))
    A("")

    # 5.13 Creativity penalty
    A("### 5.13 `13_creativity_penalty.png` — Field Accuracy by Guided/Unguided\n")
    A("**Shows.** Per-model vendor and product accuracy, split by guided/unguided.\n")
    A("**Interpretation.** Compares vendor and product accuracy to detect changes "
      "that may not be visible in aggregate `match_score`.\n")
    if not llm.empty and llm["guided"].nunique() >= 2:
        cp = (llm.groupby(["model_short", "guided"])
                .agg(Vendor=("vendor_correct", "mean"),
                     Product=("product_correct", "mean"))
                .reset_index())
        cp["Mode"] = cp["guided"].map({True: "Guided", False: "Unguided"})
        cp = cp.drop(columns=["guided"]).rename(
            columns={"model_short": "Model"})\
            [["Model", "Mode", "Vendor", "Product"]]\
            .sort_values(["Model", "Mode"])
        A(_df_to_md(cp, fmts={"Model": "s", "Mode": "s",
                               "Vendor": ".1%", "Product": ".1%"}))
    A("")

    # 5.14 Temperature sensitivity
    A("### 5.14 `14_temperature_sensitivity.png` — σ vs Temperature\n")
    A("**Shows.** Mean within-condition standard deviation of `match_score` "
      "across repeated trials, lined per model, x = `temperature`.\n")
    A("**Interpretation.** Measures how within-condition variance changes as "
      "temperature rises.\n")
    if not llm.empty and llm["temperature"].nunique() >= 2:
        grp = (llm.groupby(["model_short", "temperature", "scan_id", "prompt_name"])
                  ["match_score"]
                  .agg(["std", "count"])
                  .reset_index())
        grp = grp[grp["count"] >= 2].dropna(subset=["std"])
        if not grp.empty:
            ts_summary = (grp.groupby(["model_short", "temperature"])["std"]
                            .mean()
                            .reset_index()
                            .rename(columns={"model_short": "Model",
                                             "temperature": "Temp",
                                             "std": "mean_σ"}))
            A(_df_to_md(ts_summary, fmts={"Model": "s", "Temp": ".2f",
                                           "mean_σ": ".4f"}))
        else:
            A("_Insufficient repeated-trial groups (need ≥2 trials per condition)._")
    else:
        A("_Single temperature only — skipped._")
    A("")

    # 5.15 Accuracy funnel
    A("### 5.15 `15_accuracy_funnel.png` — CPE Hierarchy Drop-off\n")
    A("**Shows.** Per-model line over [Part → Vendor → Product → Version] accuracy.\n")
    A("**Interpretation.** Shows the field at which identification accuracy "
      "decreases across the CPE hierarchy.\n")
    if not llm.empty:
        af = (llm.groupby("model_short")
                .agg(Part=("part_correct", "mean"),
                     Vendor=("vendor_correct", "mean"),
                     Product=("product_correct", "mean"),
                     Version=("version_correct", "mean"))
                .sort_values("Vendor", ascending=False)
                .reset_index()
                .rename(columns={"model_short": "Model"}))
        A(_df_to_md(af, fmts={"Model": "s", "Part": ".1%", "Vendor": ".1%",
                               "Product": ".1%", "Version": ".1%"}))
    A("")

    # 5.16 Hallucination index
    A("### 5.16 `16_hallucination_index.png` — Hallucination Index\n")
    A("**Shows.** Per-model bars: total hallucination rate (CPE emitted, vendor "
      "wrong, score=0) and a hatched overlay for vendor-right-product-invented.\n")
    A("**Interpretation.** Incorrect CPEs can produce invalid downstream CVE "
      "lookups; lower rates are preferable.\n")
    if not llm.empty:
        has_pred = llm["predicted_cpe"].fillna("").astype(bool)
        vendor_only = (has_pred & (llm["vendor_correct"] == 1)
                                & (llm["product_correct"] == 0)).astype(int)
        hi = (pd.DataFrame({"model_short": llm["model_short"],
                             "Total_Halluc":      llm["is_hallucination"],
                             "Vendor_Only_Invent": vendor_only})
               .groupby("model_short").mean()
               .sort_values("Total_Halluc", ascending=False)
               .reset_index()
               .rename(columns={"model_short": "Model"}))
        A(_df_to_md(hi, fmts={"Model": "s", "Total_Halluc": ".1%",
                               "Vendor_Only_Invent": ".1%"}))
    A("")

    # 5.17 Payload vs score
    A("### 5.17 `17_payload_vs_score.png` — Payload Size vs Match Score\n")
    A("**Shows.** Scatter of `payload_chars` vs `match_score`, per-model linear "
      "trend lines.\n")
    A("**Interpretation.** Tests whether longer nmap payloads are associated "
      "with lower match scores. The slope sign is reported per model.\n")
    if not llm.empty and llm["payload_chars"].nunique() >= 3:
        rows = []
        for m, sub in llm.groupby("model_short"):
            if len(sub) < 5 or sub["payload_chars"].std() == 0:
                continue
            slope, _ = np.polyfit(sub["payload_chars"], sub["match_score"], 1)
            r = _safe_corr(sub["payload_chars"], sub["match_score"])
            rows.append({"Model": m,
                         "Pearson_r": r,
                         "Slope_per_1k_chars": slope * 1000.0,
                         "n": len(sub)})
        if rows:
            tr = pd.DataFrame(rows).sort_values("Pearson_r")
            A(_df_to_md(tr, fmts={"Model": "s", "Pearson_r": "+.3f",
                                   "Slope_per_1k_chars": "+.4f", "n": "d"}))
    A("")

    # 5.18 Intensity performance
    A("### 5.18 `18_intensity_performance.png` — Intensity vs Accuracy\n")
    A("**Shows.** Mean `match_score` per scan `intensity`, lined per model.\n")
    A("**Interpretation.** Compares accuracy gains with the additional time and "
      "network activity required by higher-intensity scans.\n")
    if not llm.empty and llm["intensity"].notna().sum() > 0 and llm["intensity"].nunique() >= 2:
        ip = (llm.groupby(["model_short", "intensity"])["match_score"]
                .mean()
                .unstack())
        A("**Mean match_score by intensity (rows = models, cols = intensity):**")
        ip_disp = ip.reset_index().rename(columns={"model_short": "Model"})
        A(_df_to_md(ip_disp, fmts={"Model": "s",
                                    **{c: ".3f" for c in ip.columns}}))
        A("\n**Cross-model mean by intensity:**")
        A(_series_to_md(ip.mean(axis=0), value_name="mean_score", fmt=".3f",
                        index_name="intensity"))
    A("")

    # 5.19 Vendor bias
    A("### 5.19 `19_vendor_bias.png` — Manufacturer × Model\n")
    A("**Shows.** Heatmap of mean `match_score` for each (manufacturer, model) cell.\n")
    A("**Interpretation.** Identifies manufacturer-specific differences in "
      "model accuracy.\n")
    if not llm.empty and llm["manufacturer"].nunique() >= 2:
        vb = (llm.groupby(["manufacturer", "model_short"])["match_score"]
                .mean().unstack())
        A("**Manufacturer mean (overall difficulty, sorted desc):**")
        A(_series_to_md(vb.mean(axis=1).sort_values(ascending=False),
                        value_name="mean_score", fmt=".3f",
                        index_name="manufacturer"))
        A("\n**Per-manufacturer best model:**")
        best_per_mfr = vb.idxmax(axis=1)
        bm = pd.DataFrame({"manufacturer": best_per_mfr.index,
                            "best_model":   best_per_mfr.values,
                            "score":        [vb.loc[m, best_per_mfr[m]]
                                             if pd.notna(best_per_mfr[m]) else np.nan
                                             for m in best_per_mfr.index]})
        A(_df_to_md(bm, fmts={"manufacturer": "s", "best_model": "s",
                               "score": ".3f"}))
    A("")

    # 5.20 Baseline lift
    A("### 5.20 `20_baseline_lift.png` — Lift over nmap baseline\n")
    A("**Shows.** Per-model mean of `baseline_lift` (per-scan match_score minus "
      "the mean nmap_baseline match_score for the same scan).\n")
    A("**Interpretation.** Positive values exceed the raw nmap baseline for the "
      "same scans; negative values fall below it.\n")
    bl = (llm[llm["baseline_lift"].notna()]
            .groupby("model_short")["baseline_lift"]
            .mean()
            .sort_values(ascending=False))
    if not bl.empty:
        A(_series_to_md(bl, value_name="mean_lift", fmt="+.3f",
                        index_name="Model"))
        helping = (bl > 0).sum()
        hurting = (bl < 0).sum()
        A(f"\n_Models lifting over baseline: {helping} · "
          f"models hurting vs baseline: {hurting} · "
          f"net_total_models: {len(bl)}._")
    A("")

    # 5.21 Family summary
    A("### 5.21 `21_family_summary.png` — Family Box + per-model dots\n")
    A("**Shows.** Boxplot of per-model means within each family, with each "
      "individual model overlaid as a dot.\n")
    A("**Interpretation.** Summarizes family-level performance while retaining "
      "the within-family spread across individual models.\n")
    if not llm.empty and llm["model_family"].nunique() >= 2:
        per_model = (llm.groupby(["model_family", "model_short"])["match_score"]
                       .mean()
                       .reset_index())
        fs = (per_model.groupby("model_family")["match_score"]
                       .agg(["mean", "std", "min", "max", "count"])
                       .sort_values("mean", ascending=False)
                       .reset_index()
                       .rename(columns={"model_family": "Family",
                                        "count": "n_models"}))
        A(_df_to_md(fs, fmts={"Family": "s", "mean": ".3f", "std": ".3f",
                               "min": ".3f", "max": ".3f", "n_models": "d"}))
    A("")

    # 5.22 Metric correlation
    A("### 5.22 `22_metric_correlation.png` — Metric Correlation Matrix\n")
    A("**Shows.** Pearson correlation heatmap among match_score, exact_match, "
      "vendor/product/version, cve_valid, is_hallucination, raw_clean_json, "
      "and payload_chars.\n")
    A("**Interpretation.** Identifies metrics that move together and metrics "
      "that capture distinct behavior.\n")
    cols = ["match_score", "exact_match", "vendor_correct", "product_correct",
            "version_correct", "cve_valid", "is_hallucination",
            "raw_clean_json", "payload_chars"]
    cols = [c for c in cols if c in df.columns]
    sub = df[cols].apply(pd.to_numeric, errors="coerce").dropna()
    if not sub.empty and sub.shape[1] >= 2:
        corr = sub.corr(method="pearson")
        cm = corr.reset_index().rename(columns={"index": "metric"})
        A(_df_to_md(cm, fmts={"metric": "s",
                               **{c: "+.2f" for c in corr.columns}}))
        # List the strongest pairs.
        pairs = []
        for i, a_ in enumerate(corr.columns):
            for j, b_ in enumerate(corr.columns):
                if j <= i:
                    continue
                pairs.append((a_, b_, corr.iloc[i, j]))
        pairs.sort(key=lambda t: -abs(t[2]))
        A("\n**Top |r| pairs:**")
        for a_, b_, r in pairs[:8]:
            A(f"- `{a_}` ↔ `{b_}`: r = {r:+.3f}")
    A("")

    # 5.23 Size scaling
    A("### 5.23 `23_size_scaling.png` — Parameter Count vs Score\n")
    A("**Shows.** Scatter of `model_size_b` (log-x) vs mean `match_score`, with "
      "log-linear fit and per-family colours.\n")
    A("**Interpretation.** Tests whether parameter count is associated with CPE "
      "accuracy for this dataset.\n")
    if not llm.empty:
        per = (llm.groupby(["model_short", "model_family"])
                  .agg(Score=("match_score", "mean"),
                       Size_B=("model_size_b", "first"))
                  .reset_index()
                  .rename(columns={"model_short": "Model",
                                   "model_family": "Family"}))
        sized = per[per["Size_B"].notna()]
        if len(sized) >= 3 and sized["Size_B"].nunique() >= 2:
            log_x = np.log10(sized["Size_B"].values)
            slope, intercept = np.polyfit(log_x, sized["Score"].values, 1)
            r = _safe_corr(log_x, sized["Score"].values)
            A(f"**Log-linear fit:** match_score ≈ {slope:+.3f}·log10(size_B) "
              f"+ {intercept:.3f} · Pearson r = {r:+.3f} · n = {len(sized)}")
        unsized = per[per["Size_B"].isna()]["Model"].tolist()
        if unsized:
            A(f"\n**Models without parseable size:** {', '.join(sorted(unsized))}")
    A("")

    # 5.24 Hallucination drivers
    A("### 5.24 `24_hallucination_drivers.png` — Hallucination Drivers\n")
    A("**Shows.** 2×2 grid of family-level hallucination rate vs guided, doubled, "
      "temperature, and payload-size quintile.\n")
    A("**Interpretation.** Compares hallucination rates across the experimental "
      "settings.\n")
    if not llm.empty:
        if llm["guided"].nunique() >= 2:
            gh = (llm.groupby(["model_family", "guided"])["is_hallucination"]
                    .mean().unstack())
            gh.columns = ["Unguided" if c is False else "Guided" for c in gh.columns]
            A("**Hallucination rate by guided × family:**")
            A(_df_to_md(gh.reset_index().rename(columns={"model_family": "Family"}),
                        fmts={"Family": "s",
                              **{c: ".1%" for c in gh.columns}}))
        if llm["doubled"].nunique() >= 2:
            dh2 = (llm.groupby(["model_family", "doubled"])["is_hallucination"]
                     .mean().unstack())
            dh2.columns = ["Single" if c is False else "Doubled" for c in dh2.columns]
            A("\n**Hallucination rate by doubled × family:**")
            A(_df_to_md(dh2.reset_index().rename(columns={"model_family": "Family"}),
                        fmts={"Family": "s",
                              **{c: ".1%" for c in dh2.columns}}))
        if llm["temperature"].nunique() >= 2:
            th = (llm.groupby("temperature")["is_hallucination"]
                    .mean()
                    .sort_index())
            A("\n**Hallucination rate by temperature (cross-model):**")
            A(_series_to_md(th, value_name="halluc_rate", fmt=".1%",
                            index_name="temperature"))
    A("")

    # 5.25 Cloud vs local
    A("### 5.25 `25_cloud_vs_local.png` — Cloud vs Local per Family\n")
    A("**Shows.** For each family, mean match_score and hallucination rate "
      "split by cloud vs local hosting.\n")
    A("**Interpretation.** Compares local and cloud-hosted model performance "
      "within each family.\n")
    if not llm.empty and llm["is_cloud"].nunique() >= 2:
        cv = (llm.groupby(["model_family", "is_cloud"])
                .agg(Score=("match_score", "mean"),
                     Halluc=("is_hallucination", "mean"),
                     n_models=("model_short", "nunique"))
                .reset_index())
        cv["Hosting"] = cv["is_cloud"].map({True: "Cloud", False: "Local"})
        cv = cv.drop(columns=["is_cloud"])\
                .rename(columns={"model_family": "Family"})\
                [["Family", "Hosting", "Score", "Halluc", "n_models"]]\
                .sort_values(["Family", "Hosting"])
        A(_df_to_md(cv, fmts={"Family": "s", "Hosting": "s",
                               "Score": ".3f", "Halluc": ".1%",
                               "n_models": "d"}))
    A("")

    # ── 6. Cross-cutting relationships ──────────────────────────────────────
    A("## 6. Cross-cutting relationships (no single chart)\n")

    A("### 6.1 Family-level baseline lift\n")
    if not llm.empty and llm["baseline_lift"].notna().any():
        fl = (llm[llm["baseline_lift"].notna()]
                .groupby("model_family")["baseline_lift"]
                .mean()
                .sort_values(ascending=False))
        A(_series_to_md(fl, value_name="mean_lift", fmt="+.3f",
                        index_name="Family"))
    A("")

    A("### 6.2 Doubled × Guided interaction (mean match_score, LLM rows)\n")
    if not llm.empty and llm["doubled"].nunique() >= 2 and llm["guided"].nunique() >= 2:
        ix = (llm.groupby(["doubled", "guided"])["match_score"]
                .mean().unstack())
        A(_df_to_md(ix.reset_index(),
                    fmts={"doubled": "s",
                          **{c: ".3f" for c in ix.columns}}))
    else:
        A("_Insufficient variation to compute the interaction._")
    A("")

    A("### 6.3 Temperature × prompt_name interaction (LLM rows)\n")
    if not llm.empty and llm["temperature"].nunique() >= 2:
        tp = (llm.groupby(["prompt_name", "temperature"])["match_score"]
                .mean().unstack())
        A(_df_to_md(tp.reset_index(),
                    fmts={"prompt_name": "s",
                          **{c: ".3f" for c in tp.columns}}))
    A("")

    A("### 6.4 Hallucination vs guided × doubled (cross-model)\n")
    if not llm.empty and llm["guided"].nunique() >= 2 and llm["doubled"].nunique() >= 2:
        hgd = (llm.groupby(["guided", "doubled"])["is_hallucination"]
                 .mean().unstack())
        A(_df_to_md(hgd.reset_index(),
                    fmts={"guided": "s",
                          **{c: ".1%" for c in hgd.columns}}))
    A("")

    # ── 7. Glossary ─────────────────────────────────────────────────────────
    A("## 7. Glossary\n")
    A("- **CPE** — Common Platform Enumeration; structured identifier for "
      "hardware/software products (e.g. `cpe:2.3:o:cisco:ios:15.2`). The "
      "model's job is to emit one given an nmap scan.")
    A("- **match_score** — Weighted hierarchical similarity ∈ [0, 1]. Counts "
      "partial credit for getting vendor/product right but version wrong.")
    A("- **best_tier** — `exact` (full string match) > `partial` (some fields "
      "right) > `related` (lookups suggest a connection) > `none`.")
    A("- **baseline_lift** — `match_score − mean(nmap_baseline match_score)` "
      "for the same scan_id. Positive = the LLM helped on that scan.")
    A("- **guided decoding** — output is regex-constrained to the CPE shape; "
      "trades expressivity for guaranteed format compliance.")
    A("- **doubled prompt** — the prompt and scan payload are repeated in one "
      "user message.")
    A("- **persona vs neutral** — whether the prompt opens with role-play "
      "framing (`You are an expert security analyst…`) or a flat instruction.")
    A("- **structured vs minimal** — whether the prompt asks for a fielded "
      "JSON object or a free-form CPE string.")
    A("- **hallucination** — model emits a CPE, gets the vendor wrong, and "
      "scores 0. These predictions can invalidate downstream CVE lookups.")
    A("- **clean JSON** — `raw_output` parses without any repair pass; a "
      "purely format-compliance signal.")
    A("- **intensity** — leading integer parsed from `scan_name`; "
      "monotonically tracks scan aggressiveness.")
    A("")

    path = out_dir / "context.md"
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse LLM CPE prediction results and generate an HTML report.")
    parser.add_argument("--config",  default="config.toml",
                        help="Path to config.toml (default: config.toml)")
    parser.add_argument("--output",  default=None,
                        help="Output directory (default: exports/analysis_<timestamp>)")
    parser.add_argument("--plot", type=int, action="append", default=None,
                        metavar="N",
                        help="Run only plot N (1-indexed, matches the NN_ "
                             "filename prefix). Repeatable. Skips HTML report "
                             "and LLM context generation.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    print("Connecting to MongoDB…")
    db = connect_db(cfg)

    print("Loading scored runs…")
    df = build_dataframe(db)
    print(f"  {len(df):,} prediction rows · "
          f"{df['run_id'].nunique()} runs · "
          f"{df['model_short'].nunique()} models · "
          f"{df['device_code'].nunique()} devices")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path("exports") / f"analysis_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output → {out_dir}/")

    print("Generating plots…")
    plots = {}
    steps = [
        # Existing
        ("model_comparison",       plot_model_comparison),
        ("field_accuracy",         plot_field_accuracy),
        ("tier_breakdown",         plot_tier_breakdown),
        ("score_distribution",     plot_score_distribution),
        ("prompt_ablation",        plot_prompt_ablation),
        ("doubled_effect",         plot_doubled_effect),
        ("device_heatmap",         plot_device_heatmap),
        ("scan_type",              plot_scan_type),
        ("exact_and_cve",          plot_exact_and_cve),
        ("trial_variance",         plot_trial_variance),
        # New
        ("consistency_delta",      plot_consistency_delta),
        ("guided_vs_unguided",     plot_guided_vs_unguided),
        ("creativity_penalty",     plot_creativity_penalty),
        ("temperature_sensitivity",plot_temperature_sensitivity),
        ("accuracy_funnel",        plot_accuracy_funnel),
        ("hallucination_index",    plot_hallucination_index),
        ("payload_vs_score",       plot_payload_vs_score),
        ("intensity_performance",  plot_intensity_performance),
        ("vendor_bias",            plot_vendor_bias),
        ("baseline_lift",          plot_baseline_lift),
        # New associations / cross-cuts
        ("family_summary",         plot_family_summary),
        ("metric_correlation",     plot_metric_correlation),
        ("size_scaling",           plot_size_scaling),
        ("hallucination_drivers",  plot_hallucination_drivers),
        ("cloud_vs_local",         plot_cloud_vs_local),
    ]
    if args.plot:
        selected = sorted(set(args.plot))
        invalid = [n for n in selected if n < 1 or n > len(steps)]
        if invalid:
            parser.error(f"--plot index out of range (valid: 1-{len(steps)}): "
                         f"{invalid}")
        steps = [steps[n - 1] for n in selected]
        print(f"  Filtering to plots: {selected}")
    for name, fn in steps:
        try:
            result = fn(df, out_dir)
            plots[name] = result
            status = "ok" if result else "skipped"
        except Exception as exc:
            plots[name] = ""
            status = f"FAILED ({exc})"
        print(f"  {name:25s} {status}")

    if args.plot:
        print(f"\nDone (plots only).")
        print(f"  PNGs    : {out_dir}/*.png")
        return

    summary     = compute_summary(df)
    model_table = compute_model_table(df)

    print("Building HTML report…")
    report = generate_report(summary, model_table, plots, out_dir, ts)

    print("Building LLM context document…")
    context = generate_llm_context_doc(df, summary, model_table, out_dir, ts)

    print(f"\nDone.")
    print(f"  Report  : {report}")
    print(f"  Context : {context}")
    print(f"  PNGs    : {out_dir}/*.png")


if __name__ == "__main__":
    main()

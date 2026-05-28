#!/usr/bin/env python3
"""
Create the thesis device x model heatmap as tiered panels.

By default this reads the newest exports/thesis_data_*.xlsx file, using the
frozen 00_predictions_long sheet that export_thesis_data.py writes for the
thesis. Use --source db to rebuild the dataframe from MongoDB instead.

Examples:
    python plot_tiered_device_heatmap.py
    python plot_tiered_device_heatmap.py --xlsx exports/thesis_data_20260515_185048.xlsx
    python plot_tiered_device_heatmap.py --source db --output img/07_device_heatmap_tiered.png
"""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import pandas as pd
import seaborn as sns


EXCLUDED_MODELS = {"qwen3.5:cloud"}
EXCLUDED_DEVICES = {"Nintendo_WiiU", "WiFi_Repeater_Repeater_Mode"}

MODEL_TIERS = ["Frontier API", "Ollama Cloud", "Local vLLM"]
TIER_TITLES = {
    "Frontier API": "Frontier API",
    "Ollama Cloud": "Ollama Cloud",
    "Local vLLM": "Local vLLM",
    "Nmap baseline": "Nmap baseline",
}


def classify_model_tier(model_short: str, model_full: str | None = None) -> str:
    """Classify one model into the display tier used by the heatmap panels."""
    full = (model_full or model_short or "").lower()
    short = (model_short or "").lower()
    key = f"{full} {short}"

    if "nmap" in key:
        return "Nmap baseline"
    if "cloud" in key:
        return "Ollama Cloud"
    if "gpt-oss" in key:
        return "Local vLLM"
    if (
        "claude" in key
        or "anthropic" in key
        or "gemini" in key
        or "gpt-5" in key
        or "openai/gpt" in key
    ):
        return "Frontier API"
    return "Local vLLM"


def latest_thesis_export(root: Path) -> Path:
    candidates = sorted(
        (root / "exports").glob("thesis_data_*.xlsx"),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        raise FileNotFoundError("No exports/thesis_data_*.xlsx files found.")
    return candidates[-1]


def load_from_xlsx(path: Path) -> pd.DataFrame:
    return pd.read_excel(path, sheet_name="00_predictions_long")


def load_from_db(config: str) -> pd.DataFrame:
    from analyze import build_dataframe, connect_db, load_config

    cfg = load_config(config)
    return build_dataframe(connect_db(cfg))


def apply_thesis_filter(df: pd.DataFrame, include_baseline: bool) -> pd.DataFrame:
    out = df.copy()

    if "trial" in out.columns:
        out = out[out["trial"] == 1]
    if "model_short" in out.columns:
        out = out[~out["model_short"].isin(EXCLUDED_MODELS)]
    if "device_code" in out.columns:
        out = out[~out["device_code"].isin(EXCLUDED_DEVICES)]
    if not include_baseline:
        out = out[out["prompt_name"] != "nmap_baseline"]
        out = out[~out["model_short"].astype(str).str.lower().str.contains("nmap")]

    return out.reset_index(drop=True)


def add_model_tier(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "model" not in out.columns:
        out["model"] = out["model_short"]
    model_meta = (
        out.drop_duplicates("model_short")
        .set_index("model_short")["model"]
        .to_dict()
    )
    out["model_tier"] = out["model_short"].map(
        lambda m: classify_model_tier(m, model_meta.get(m))
    )
    return out


def has_cpe_rate(df: pd.DataFrame) -> pd.DataFrame:
    """Return device x model rate of runs that emitted at least one CPE."""
    work = df.copy()
    work["_has_cpe"] = (
        work["predicted_cpe"]
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
    )

    if "run_id" in work.columns:
        run_level = (
            work.groupby(["run_id", "device_code", "model_short"], as_index=False)
            ["_has_cpe"]
            .any()
        )
    else:
        run_level = work[["device_code", "model_short", "_has_cpe"]]

    return (
        run_level.groupby(["device_code", "model_short"])["_has_cpe"]
        .mean()
        .unstack()
    )


def wrapped_labels(labels: list[str], width: int = 18) -> list[str]:
    wrapped = []
    for label in labels:
        text = str(label)
        wrapped.append("\n".join(textwrap.wrap(text, width=width)) or text)
    return wrapped


def overlay_no_cpe(ax, no_cpe_mask: pd.DataFrame) -> None:
    for y, row in enumerate(no_cpe_mask.index):
        for x, col in enumerate(no_cpe_mask.columns):
            if bool(no_cpe_mask.loc[row, col]):
                ax.add_patch(
                    Rectangle(
                        (x, y),
                        1,
                        1,
                        facecolor="#e9ecef",
                        edgecolor="#6c757d",
                        hatch="////",
                        linewidth=0.0,
                        alpha=0.9,
                        zorder=3,
                    )
                )


def plot_tiered_heatmap(
    df: pd.DataFrame,
    output: Path,
    include_baseline: bool,
    no_cpe_threshold: float,
    title: str,
) -> None:
    df = add_model_tier(df)

    tiers = MODEL_TIERS.copy()
    if include_baseline and (df["model_tier"] == "Nmap baseline").any():
        tiers.append("Nmap baseline")

    score = (
        df.groupby(["device_code", "model_short"], observed=True)["match_score"]
        .mean()
        .unstack()
    )
    cpe_rate = has_cpe_rate(df)

    device_order = score.mean(axis=1).sort_values(ascending=False).index.tolist()
    model_means = df.groupby("model_short", observed=True)["match_score"].mean()
    models_by_tier: dict[str, list[str]] = {}
    for tier in tiers:
        tier_models = sorted(
            df.loc[df["model_tier"] == tier, "model_short"].dropna().unique(),
            key=lambda m: model_means.get(m, -1),
            reverse=True,
        )
        if tier_models:
            models_by_tier[tier] = tier_models

    if not models_by_tier:
        raise ValueError("No model tiers contained data after filtering.")

    n_tiers = len(models_by_tier)
    tier_heights = [len(models) for models in models_by_tier.values()]

    sns.set_theme(style="white", font_scale=0.9)
    fig = plt.figure(figsize=(8.0, 10.5))
    grid = fig.add_gridspec(
        n_tiers,
        2,
        height_ratios=tier_heights,
        width_ratios=[1.0, 0.035],
        hspace=0.14,
        wspace=0.02,
    )
    cbar_ax = fig.add_subplot(grid[:, -1])

    for i, (tier, models) in enumerate(models_by_tier.items()):
        ax = fig.add_subplot(grid[i, 0])
        is_last = i == n_tiers - 1

        # Transpose: models on rows (Y), devices on columns (X).
        panel = score.reindex(index=device_order, columns=models).T
        panel_cpe = cpe_rate.reindex(index=device_order, columns=models).T
        no_cpe = (panel_cpe <= no_cpe_threshold) & panel.notna()

        sns.heatmap(
            panel,
            ax=ax,
            cmap="RdYlGn",
            vmin=0,
            vmax=1,
            linewidths=0.25,
            linecolor="white",
            cbar=is_last,
            cbar_ax=cbar_ax if is_last else None,
            xticklabels=device_order if is_last else False,
            yticklabels=models,
            # cbar_kws={"label": "Mean match score"},
        )
        overlay_no_cpe(ax, no_cpe)

        ax.set_title(
            f"{TIER_TITLES.get(tier, tier)}  ({len(models)} models)",
            pad=6,
            fontsize=11,
            fontweight="bold",
            loc="left",
        )
        ax.set_xlabel("")
        ax.set_ylabel("")
        ax.set_yticks([j + 0.5 for j in range(len(models))])
        ax.set_yticklabels(models, rotation=0, fontsize=8)
        if is_last:
            ax.set_xticks([j + 0.5 for j in range(len(device_order))])
            ax.set_xticklabels(device_order, rotation=55, ha="right", fontsize=8)
        else:
            ax.set_xticklabels([])
            ax.tick_params(axis="x", length=0)

    cbar_ax.tick_params(labelsize=8)
    # cbar_ax.set_ylabel("Mean match score", fontsize=9)
    fig.suptitle(title, fontsize=13, fontweight="bold", y=0.945)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=300, bbox_inches="tight")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a tiered device x model heatmap for the thesis."
    )
    parser.add_argument(
        "--source",
        choices=["xlsx", "db"],
        default="xlsx",
        help="Read the frozen thesis export or rebuild from MongoDB (default: xlsx).",
    )
    parser.add_argument(
        "--xlsx",
        default=None,
        help="Path to thesis_data_*.xlsx. Defaults to the newest file in exports/.",
    )
    parser.add_argument("--config", default="config.toml", help="Path to config.toml.")
    parser.add_argument(
        "--output",
        default="img/07_device_heatmap_tiered.png",
        help="Output PNG path.",
    )
    parser.add_argument(
        "--include-baseline",
        action="store_true",
        help="Include the nmap baseline as its own small panel.",
    )
    parser.add_argument(
        "--no-cpe-threshold",
        type=float,
        default=0.05,
        help="Hatch cells whose run-level CPE emission rate is at or below this value.",
    )
    parser.add_argument(
        "--title",
        default="Mean Match Score by Device and Model Tier",
        help="Figure title.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parent

    if args.source == "xlsx":
        xlsx = Path(args.xlsx) if args.xlsx else latest_thesis_export(root)
        print(f"Reading {xlsx}")
        df = load_from_xlsx(xlsx)
    else:
        print("Reading MongoDB via analyze.py")
        df = load_from_db(args.config)

    df = apply_thesis_filter(df, include_baseline=args.include_baseline)
    print(
        f"Plotting {df['device_code'].nunique()} devices x "
        f"{df['model_short'].nunique()} models from {len(df):,} prediction rows"
    )
    plot_tiered_heatmap(
        df=df,
        output=Path(args.output),
        include_baseline=args.include_baseline,
        no_cpe_threshold=args.no_cpe_threshold,
        title=args.title,
    )
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

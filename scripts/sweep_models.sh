#!/usr/bin/env bash
# ------------------------------------------------------------------
# sweep_models.sh — run every model in the MODELS array against
# every scan in the database. Uses run.py's --model flag, so
# config.toml is left untouched.
#
# For each model:
#   1. `ollama pull <model>` (no-op if already cached)
#   2. for each scan_id: `run.py <scan_id> --model <model>`
#
# Edit the MODELS array below to choose what to sweep.
# ------------------------------------------------------------------
set -euo pipefail
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

MODELS=(
  deepseek-v4-flash
  deepseek-v4-pro
  kimi-k2.6
  glm-5.1
  gemma4
  qwen3.5
  qwen3-coder-next
  ministral-3
  devstral-small-2
  nemotron-3-super
  qwen3-next
  kimi-k2.5
  rnj-1
  minimax-m2.7
  glm-5
)

mapfile -t SCAN_IDS < <(python -c 'from db import get_db; [print(s["_id"]) for s in get_db().scans.find({}, {"_id":1}).sort("_id")]')

if [[ ${#SCAN_IDS[@]} -eq 0 ]]; then
  echo "No scans in the database. Run scripts/bootstrap_db.sh first." >&2
  exit 1
fi

echo "Sweeping ${#MODELS[@]} model(s) x ${#SCAN_IDS[@]} scan(s)"

for raw in "${MODELS[@]}"; do
  model="${raw}:cloud"
  echo
  echo "============================================================"
  echo "  MODEL: $model"
  echo "============================================================"
  ollama pull "$model"

  for scan_id in "${SCAN_IDS[@]}"; do
    echo
    echo "---- $model :: scan_id=$scan_id ----"
    python run.py "$scan_id" --model "$model"
  done
done

echo
echo "All models complete."

#!/usr/bin/env bash
# ------------------------------------------------------------------
# bootstrap_db.sh — populate an empty MongoDB from scratch.
#
# Steps:
#   1. init.py            — create collections + indexes
#   2. seed_prompts.py    — insert prompts from PROMPTS list
#   3. ingest.py *.xml    — every XML under scans/<device>/<run>/*.xml,
#                            tagged with the device-code (= directory name)
#   4. truth.py           — concatenate per-device scans/*/Truth.toml
#                            into a single truth.toml, load it, then delete
#
# Run from inside the activated venv. Idempotent — safe to re-run.
# ------------------------------------------------------------------
set -euo pipefail
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

python init.py
python seed_prompts.py

# Every device dir under scans/ — directory name is the device_code,
# XMLs live one timestamped subdir deep: scans/<device>/<run>/*.xml
shopt -s nullglob
for dir in scans/*/; do
  device_code=$(basename "$dir")
  for xml in "$dir"*/*.xml; do
    python ingest.py "$xml" "$device_code"
  done
done
shopt -u nullglob

# Concatenate per-device Truth.toml files and load them.
awk 'FNR==1 && NR>1 { print "" } { print }' scans/*/Truth.toml > truth.toml
python truth.py
rm -f truth.toml

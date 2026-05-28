#!/usr/bin/env bash
# ------------------------------------------------------------------
# sweep_scans.sh — run the model currently configured in config.toml
# across every scan in the database.
#
# This is the SINGLE-MODEL sweep. It does NOT pass --model — run.py
# reads [model].name from config.toml. Edit config.toml first, then
# launch this script.
#
# For each scan_id, run.py performs both the normal and the doubled
# pass for every prompt in the DB. Existing model_runs are preserved;
# trial_number auto-increments per (scan, prompt, doubled, model).
#
# For multi-model sweeps, see sweep_models.sh (--model flag).
# ------------------------------------------------------------------
set -euo pipefail
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

PY=.venv/bin/python

echo "Fetching scan IDs from database..."

# Get all scan IDs from MongoDB
scan_ids=$($PY -c "
from db import get_db
db = get_db()
ids = [str(s['_id']) for s in db.scans.find({}, {'_id': 1})]
print(' '.join(ids))
")

if [ -z "$scan_ids" ]; then
    echo "No scans found in database. Run scripts/bootstrap_db.sh first."
    exit 1
fi

echo "Found scans: $scan_ids"
echo ""

# Run sweep for each scan
for scan_id in $scan_ids; do
    echo "========================================"
    echo "Running sweep for scan_id=$scan_id"
    echo "========================================"
    $PY run.py "$scan_id"
    echo ""
done

echo "All sweeps complete!"

# ------------------------------------------------------------------
# sweep_scans.ps1 — run the model currently configured in config.toml
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
# For multi-model sweeps, see sweep_models.ps1 (--model flag) or
# sweep_models_config_swap.ps1 (rewrites config.toml in place).
# ------------------------------------------------------------------
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$PY = if (Test-Path ".w-venv/Scripts/python.exe") { ".w-venv/Scripts/python.exe" } elseif (Test-Path ".venv/Scripts/python.exe") { ".venv/Scripts/python.exe" } else { ".venv/bin/python" }

Write-Host "Fetching scan IDs from database..."

# Get all scan IDs from MongoDB
$scan_ids = & $PY -c "
from db import get_db
db = get_db()
ids = [str(s['_id']) for s in db.scans.find({}, {'_id': 1})]
print(' '.join(ids))
"

if ([string]::IsNullOrWhiteSpace($scan_ids)) {
    Write-Host "No scans found in database. Run scripts/bootstrap_db.ps1 first."
    exit 1
}

Write-Host "Found scans: $scan_ids"
Write-Host ""

# Run sweep for each scan
foreach ($scan_id in $scan_ids -split " ") {
    Write-Host "========================================"
    Write-Host "Running sweep for scan_id=$scan_id"
    Write-Host "========================================"
    & $PY run.py "$scan_id"
    Write-Host ""
}

Write-Host "All sweeps complete!"

# ------------------------------------------------------------------
# sweep_models_resume.ps1 — resume a sweep_models.ps1 run that stopped
# before completion (network interruption, OOM, Ctrl-C, etc.).
#
# Usage:
#   ./scripts/sweep_models_resume.ps1 -StartIndex <n> [-StartModel <name>]
#
#   -StartIndex   (required) zero-based scan index where the first model
#                 should pick up. Indexes are over scan_ids sorted by _id.
#   -StartModel   (optional) skip earlier models; only the first model
#                 in the resumed list honors -StartIndex. Subsequent
#                 models always run all scans from index 0.
#
# Edit the $models array below to match what you were sweeping.
# ------------------------------------------------------------------
param(
    [Parameter(Mandatory=$true)]
    [int]$StartIndex,
    [string]$StartModel
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$models = @(
    "deepseek-v4-pro:cloud"
)

$PY = if (Test-Path ".w-venv/Scripts/python.exe") { ".w-venv/Scripts/python.exe" } `
      elseif (Test-Path ".venv/Scripts/python.exe") { ".venv/Scripts/python.exe" } `
      else { ".venv/bin/python" }

$scan_ids_raw = & $PY -c "from db import get_db; print(' '.join(str(s['_id']) for s in get_db().scans.find({}, {'_id': 1}).sort('_id')))"
$scan_ids = $scan_ids_raw.Trim() -split '\s+'

if (-not $scan_ids -or $scan_ids.Count -eq 0 -or [string]::IsNullOrWhiteSpace($scan_ids[0])) {
    Write-Host "No scans in the database. Run scripts/bootstrap_db.ps1 first." -ForegroundColor Red
    exit 1
}

if ($StartIndex -lt 0 -or $StartIndex -ge $scan_ids.Count) {
    Write-Host "StartIndex $StartIndex out of range (0..$($scan_ids.Count - 1))." -ForegroundColor Red
    exit 1
}

$remaining_scans = $scan_ids[$StartIndex..($scan_ids.Count - 1)]

if ($StartModel) {
    $modelStartIdx = [array]::IndexOf($models, $StartModel)
    if ($modelStartIdx -lt 0) {
        Write-Host "StartModel '$StartModel' not in model list." -ForegroundColor Red
        exit 1
    }
    $models_to_run = $models[$modelStartIdx..($models.Count - 1)]
} else {
    $models_to_run = $models
}

Write-Host "Resuming sweep: $($models_to_run.Count) model(s) x $($remaining_scans.Count) scan(s) starting at index $StartIndex"

for ($i = 0; $i -lt $models_to_run.Count; $i++) {
    $model = $models_to_run[$i]

    # Only the first model honors $StartIndex; subsequent models run all scans.
    if ($i -eq 0) {
        $scans_for_this_model = $remaining_scans
    } else {
        $scans_for_this_model = $scan_ids
    }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  MODEL: $model"
    Write-Host "============================================================"
    & ollama pull $model

    foreach ($scan_id in $scans_for_this_model) {
        Write-Host ""
        Write-Host "---- $model :: scan_id=$scan_id ----"
        & $PY run.py $scan_id --model $model
    }
}

Write-Host ""
Write-Host "Resume sweep complete."

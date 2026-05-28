# ------------------------------------------------------------------
# sweep_models.ps1 — run every model in the $models array against
# every scan in the database. Uses run.py's --model flag, so
# config.toml is left untouched.
#
# For each model:
#   1. `ollama pull <model>` (no-op if already cached)
#   2. for each scan_id: `run.py <scan_id> --model <model>`
#
# Edit the $models array below to choose what to sweep. To resume
# after a mid-sweep crash, use sweep_models_resume.ps1.
# For the alternate strategy (rewrite config.toml in place rather
# than passing --model), see sweep_models_config_swap.ps1.
# ------------------------------------------------------------------
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$models = @(
    "deepseek-v4-flash:cloud",
    "deepseek-v4-pro:cloud",
    "kimi-k2.6:cloud",
    "glm-5.1:cloud",
    "gemma4:31b-cloud",
    "qwen3.5:cloud",
    "qwen3-coder-next:cloud",
    "ministral-3:3b-cloud",
    "ministral-3:8b-cloud",
    "ministral-3:14b-cloud",
    "devstral-small-2:24b-cloud".
    "kimi-k2:1t-cloud"
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

Write-Host "Sweeping $($models.Count) model(s) x $($scan_ids.Count) scan(s)"

foreach ($model in $models) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  MODEL: $model"
    Write-Host "============================================================"
    & ollama pull $model

    foreach ($scan_id in $scan_ids) {
        Write-Host ""
        Write-Host "---- $model :: scan_id=$scan_id ----"
        & $PY run.py $scan_id --model $model
    }
}

Write-Host ""
Write-Host "All models complete."

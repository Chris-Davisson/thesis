# ------------------------------------------------------------------
# sweep_models_config_swap.ps1 — multi-model sweep that rewrites
# [model].name in config.toml in place rather than passing --model.
#
# Why two ways? sweep_models.ps1 is the simple path: it just hands
# --model to run.py. THIS script is for the case where you want
# config.toml to actually reflect what's running (e.g. you're tailing
# the file, or some adjacent tool reads it).
#
# Behavior:
#   • For each model: `ollama pull` (warm-up), then rewrite the
#     [model].name line in config.toml, then run.py per scan_id
#     (no --model — run.py reads from config).
#   • Snapshots config.toml at start and ALWAYS restores it in the
#     finally{} block — even on Ctrl-C or mid-sweep crash.
#   • Set-ModelName only edits inside the [model] section. [[scans]]
#     blocks also have a `name` field and must not be touched.
#
# Edit the $models array below to choose what to sweep.
# ------------------------------------------------------------------
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$models = @(
    "qwen3.5:397b-cloud",
    "kimi-k2.6:cloud"
    # "gpt-oss:20b"
)

$PY = if (Test-Path ".w-venv/Scripts/python.exe") { ".w-venv/Scripts/python.exe" } `
      elseif (Test-Path ".venv/Scripts/python.exe") { ".venv/Scripts/python.exe" } `
      else { ".venv/bin/python" }

$ConfigPath = "config.toml"

function Set-ModelName([string]$path, [string]$newName) {
    # Only rewrite `name = "..."` inside the [model] section — [[scans]]
    # blocks also have a `name` field and must not be touched.
    $inModel = $false
    $out = foreach ($line in Get-Content $path) {
        if ($line -match '^\s*\[([^\]]+)\]') {
            $inModel = ($matches[1] -eq "model")
        }
        if ($inModel -and $line -match '^(\s*name\s*=\s*")[^"]*(".*)$') {
            $matches[1] + $newName + $matches[2]
        } else {
            $line
        }
    }
    Set-Content -Path $path -Value $out -Encoding UTF8
}

# Snapshot the config so we can restore it verbatim at the end
$originalConfig = Get-Content $ConfigPath -Raw

try {
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

    Write-Host "Scans: $scan_ids"
    Write-Host "Models: $($models -join ', ')"

    foreach ($model in $models) {
        Write-Host ""
        Write-Host "########################################"
        Write-Host "  MODEL: $model"
        Write-Host "########################################"

        Write-Host "  warming up Ollama..."
        & ollama pull $model "ready" | Out-Null

        Set-ModelName -path $ConfigPath -newName $model

        foreach ($scan_id in $scan_ids -split " ") {
            Write-Host ""
            Write-Host "---  $model  |  scan_id=$scan_id  ---"
            & $PY run.py "$scan_id"
        }
    }
}
finally {
    # Always restore original config.toml, even on error / Ctrl-C
    Set-Content -Path $ConfigPath -Value $originalConfig -Encoding UTF8 -NoNewline
    Write-Host ""
    Write-Host "Restored original config.toml."
}

Write-Host ""
Write-Host "All models swept!"

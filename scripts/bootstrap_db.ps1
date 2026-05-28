#!/usr/bin/env pwsh
# ------------------------------------------------------------------
# bootstrap_db.ps1 — populate an empty MongoDB from scratch.
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
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

python init.py
python seed_prompts.py

# Every device dir under scans/ — directory name is the device_code,
# XMLs live one timestamped subdir deep: scans/<device>/<run>/*.xml
Get-ChildItem -Path 'scans' -Directory | ForEach-Object {
    $deviceCode = $_.Name
    Get-ChildItem -Path $_.FullName -Directory |
        ForEach-Object { Get-ChildItem -Path $_.FullName -Filter '*.xml' -File -ErrorAction SilentlyContinue } |
        ForEach-Object { python ingest.py $_.FullName $deviceCode }
}

# Concatenate per-device Truth.toml files and load them.
$chunks = Get-ChildItem -Path 'scans' -Directory |
          ForEach-Object { Join-Path $_.FullName 'Truth.toml' } |
          Where-Object { Test-Path -LiteralPath $_ } |
          ForEach-Object { (Get-Content -Raw -LiteralPath $_).TrimEnd("`r","`n") }
Set-Content -LiteralPath 'truth.toml' -Value (($chunks -join "`n`n") + "`n") -NoNewline -Encoding utf8
python truth.py
Remove-Item -LiteralPath 'truth.toml' -Force -ErrorAction SilentlyContinue

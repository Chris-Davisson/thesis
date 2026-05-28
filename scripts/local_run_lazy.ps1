param(
    [Parameter(Mandatory=$true)]
    [string]$Model
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$common = @("--model", $Model, "--concurrency", "32", "--port", "8000")

python .\local_run.py @common
Start-Sleep -Seconds 5

python .\local_run.py @common --guided
Start-Sleep -Seconds 5

python .\local_run.py @common --guided --temperature 0.7
Start-Sleep -Seconds 5

python .\local_run.py @common --guided --temperature 0.7 --seed 1
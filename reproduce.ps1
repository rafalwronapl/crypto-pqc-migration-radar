param(
  [string]$Root = $PSScriptRoot,
  [string]$OutDir = (Join-Path $PSScriptRoot "reports\local_crypto_radar"),
  [switch]$Force
)

$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
  python -m pytest
  if ($LASTEXITCODE -ne 0) {
    throw "pytest failed with exit code $LASTEXITCODE"
  }
  python .\quality_gate.py --skip-pytest
  if ($LASTEXITCODE -ne 0) {
    throw "quality gate failed with exit code $LASTEXITCODE"
  }
  $scanArgs = @(".\crypto_pqc_radar.py", "--root", $Root, "--out-dir", $OutDir)
  if ($Force) {
    $scanArgs += "--force"
  }
  python @scanArgs
  if ($LASTEXITCODE -ne 0) {
    throw "scanner failed with exit code $LASTEXITCODE"
  }
  python .\benchmark_corpus.py --out (Join-Path $OutDir "benchmark_corpus.json")
  if ($LASTEXITCODE -ne 0) {
    throw "benchmark corpus failed with exit code $LASTEXITCODE"
  }
  python .\verify_crypto_radar.py --root $Root --report (Join-Path $OutDir "qday_risk_report.json") --out (Join-Path $OutDir "verifier_report.md")
  if ($LASTEXITCODE -ne 0) {
    throw "verifier failed with exit code $LASTEXITCODE"
  }
  $batchOut = Join-Path $OutDir "batch"
  if ($Force -and (Test-Path $batchOut) -and -not (Test-Path (Join-Path $batchOut ".crypto-pqc-radar-output"))) {
    Set-Content -Path (Join-Path $batchOut ".crypto-pqc-radar-output") -Value "legacy reproduce batch output marker"
  }
  $batchArgs = @(".\batch_crypto_pqc_radar.py", "--root", $Root, "--out-dir", $batchOut)
  if ($Force) {
    $batchArgs += "--force"
  }
  python @batchArgs
  if ($LASTEXITCODE -ne 0) {
    throw "batch scanner failed with exit code $LASTEXITCODE"
  }
  Write-Host "Crypto/PQC radar outputs written to $OutDir"
}
finally {
  Pop-Location
}

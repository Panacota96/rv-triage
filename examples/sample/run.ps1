# Runs the sample collection on Windows and checks the result.
# Collects examples\sample\source (a synthetic folder laid out like a Windows volume root) and fails (non-zero
# exit) if the self-test, the collection or verify-log fails, or if the package manifest
# (reports\<RUN-ID>\package\manifest.csv) differs from the independently computed expected_hashes.csv.
# Usage: .\examples\sample\run.ps1 [-Bin C:\path\to\rv-triage.exe]
param([string]$Bin = "rv-triage")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = if ($env:RV_SAMPLE_OUT) { $env:RV_SAMPLE_OUT } else { Join-Path $here "out" }
& $Bin self-test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Expected exit code 0: every file collected (COLLECTED_API, info); volatile data is not available from a folder
# (NOT_AVAILABLE_FROM_SOURCE, info). See expected_findings.json.
& $Bin collect --source (Join-Path $here "source") --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" --out $out --progress none
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$run = Get-ChildItem (Join-Path $out "logs") | Sort-Object Name | Select-Object -Last 1
& $Bin verify-log $run.FullName; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Compare the package manifest with the independently computed expected_hashes.csv: same package paths, sizes,
# SHA-256 and MD5. Any difference fails the script (exit 3).
$package = Join-Path (Join-Path (Join-Path $out "reports") $run.Name) "package"
$expected = Import-Csv (Join-Path $here "expected_hashes.csv")
$manifest = Import-Csv (Join-Path $package "manifest.csv") | Where-Object { $_.package_path -like "artifacts/*" }
$bad = 0
if (@($manifest).Count -ne @($expected).Count) {
  Write-Host "MISMATCH: the package holds $(@($manifest).Count) artifact files, expected_hashes.csv lists $(@($expected).Count)"
  $bad = 1
}
foreach ($row in $expected) {
  $got = $manifest | Where-Object { $_.package_path -ceq $row.package_path }
  if ($null -eq $got -or @($got).Count -ne 1) { Write-Host "MISMATCH: $($row.package_path) not in manifest.csv"; $bad = 1; continue }
  if ($got.bytes -ne $row.size -or $got.sha256 -ne $row.sha256 -or $got.md5 -ne $row.md5) {
    Write-Host "MISMATCH $($row.package_path): tool $($got.bytes),$($got.sha256),$($got.md5), expected $($row.size),$($row.sha256),$($row.md5)"
    $bad = 1
  }
}
if ($bad) { exit 3 }
Write-Host "manifest.csv matches expected_hashes.csv ($(@($expected).Count) files: size, SHA-256, MD5)"
Write-Host "Package: $package"
Write-Host "Reports: $(Join-Path (Join-Path $out 'reports') $run.Name)\statistics.en.html"

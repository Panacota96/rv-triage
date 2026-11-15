#!/usr/bin/env sh
# Runs the sample collection and checks the result. Usage: examples/sample/run.sh [path-to-rv-triage]
# Output folder: examples/sample/out (or $RV_SAMPLE_OUT).
# Collects examples/sample/source (a synthetic folder laid out like a Windows volume root) and fails (non-zero
# exit) if the self-test, the collection or verify-log fails, or if the package manifest
# (reports/<RUN-ID>/package/manifest.csv) differs from the independently computed expected_hashes.csv.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-triage}
out=${RV_SAMPLE_OUT:-"$here/out"}
"$bin" self-test
# Expected exit code 0: every file collected (COLLECTED_API, info); volatile data is not available from a folder
# (NOT_AVAILABLE_FROM_SOURCE, info). See expected_findings.json.
"$bin" collect --source "$here/source" --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" --out "$out" --progress none
run=$(ls "$out/logs" | tail -n 1)
"$bin" verify-log "$out/logs/$run"
# Compare the package manifest with expected_hashes.csv: same package paths, sizes, SHA-256 and MD5.
# manifest.csv: package_path,group,source,method,bytes,sha256,md5,truncated_at,findings (source may be quoted, so
# the digests are read from the right; the sample's package paths contain no comma).
awk -F, '
  FNR == 1 { next }
  FILENAME ~ /expected_hashes\.csv$/ { want[$1] = $2 "," $3 "," $4; n++; next }
  $1 ~ /^artifacts\// { got[$1] = $(NF - 4) "," $(NF - 3) "," $(NF - 2); m++ }
  END {
    for (f in want) if (got[f] != want[f]) { print "MISMATCH " f ": tool " got[f] ", expected " want[f]; bad = 1 }
    if (m != n) { print "MISMATCH: the package holds " m " artifact files, expected_hashes.csv lists " n; bad = 1 }
    if (bad) exit 3
    print "manifest.csv matches expected_hashes.csv (" n " files: size, SHA-256, MD5)"
  }' "$here/expected_hashes.csv" "$out/reports/$run/package/manifest.csv"
echo "Package: $out/reports/$run/package"
echo "Reports: $out/reports/$run/statistics.en.html"

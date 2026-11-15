#!/usr/bin/env python3
"""Writes examples/sample/expected_hashes.csv and expected_findings.json from examples/sample/source/, independently
of the Rust code (Python hashlib; the group of each file is decided here from the documented target table).

expected_hashes.csv: one row per file the package must contain under artifacts/<group>/<volume path>, with its
size, SHA-256 and MD5. volatile/system.json and the manifests are not listed: they describe the collecting host and
the run, so they differ on every run.

expected_findings.json: the finding codes a directory-source run must give, per package path, plus the volatile
group, which a folder cannot provide (NOT_AVAILABLE_FROM_SOURCE).

  python examples/sample/make_expected.py
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source"


def group(volume_path: str) -> str:
    p = volume_path.lower()
    if p.startswith("windows/system32/config/") or p.endswith("/ntuser.dat") or p.endswith("/usrclass.dat"):
        return "hives"
    if p.startswith("windows/system32/winevt/logs/"):
        return "evtx"
    if p.startswith("windows/prefetch/"):
        return "prefetch"
    if p.startswith("windows/system32/tasks/"):
        return "tasks"
    if p.startswith("users/"):
        return "browsers"
    raise SystemExit(f"no group for {volume_path}")


def main() -> None:
    rows = []
    for f in sorted(SOURCE.rglob("*")):
        if not f.is_file():
            continue
        vol = f.relative_to(SOURCE).as_posix()
        data = f.read_bytes()
        rows.append(
            (
                f"artifacts/{group(vol)}/{vol}",
                len(data),
                hashlib.sha256(data).hexdigest(),
                hashlib.md5(data).hexdigest(),
            )
        )
    rows.sort()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["package_path", "size", "sha256", "md5"])
    w.writerows(rows)
    (HERE / "expected_hashes.csv").write_text(buf.getvalue(), encoding="utf-8", newline="\n")

    findings = {
        "description": "Ground truth for `rv-triage collect --source examples/sample/source` (directory source): the "
        "finding codes of every packaged file (manifest.json collected[].findings) and of every target that is "
        "not in the package (manifest.json not_collected[].finding, keyed by group).",
        "source_kind": "directory",
        "exit_code": 0,
        "collected": {"volatile/system.json": ["COLLECTED_API"], **{r[0]: ["COLLECTED_API"] for r in rows}},
        "not_collected": {"volatile": ["NOT_AVAILABLE_FROM_SOURCE"]},
    }
    (HERE / "expected_findings.json").write_text(
        json.dumps(findings, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"{len(rows)} files: expected_hashes.csv, expected_findings.json")


if __name__ == "__main__":
    main()

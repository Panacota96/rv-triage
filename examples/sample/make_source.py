#!/usr/bin/env python3
"""Regenerates examples/sample/source/: a SMALL SYNTHETIC folder laid out like a Windows volume root, one or two
files per artifact group, so `rv-triage collect --source examples/sample/source` exercises every file group.

Every file is placeholder bytes: the right magic number at offset 0 (regf, ElfFile, MAM/SCCA, SQLite format 3,
UTF-16 task XML) followed by a plain-text banner saying it is fake. No file is a parsable artifact and none holds
real personal data; the user names (ana.ruiz, ben.test) are invented. Output is deterministic, so running this
again gives byte-identical files (expected_hashes.csv stays valid).

  python examples/sample/make_source.py          then   python examples/sample/make_expected.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE / "source"
BANNER = "RAKVOR SYNTHETIC SAMPLE - NOT A REAL ARTIFACT - NO PERSONAL DATA"


def body(magic: bytes, label: str, size: int) -> bytes:
    """`magic`, then the banner and the label, padded with dots to `size` bytes (deterministic)."""
    text = f"\0{BANNER} | {label} | ".encode("ascii")
    out = magic + text
    pad = b"." * max(0, size - len(out) - 1) + b"\n"
    return (out + pad)[: max(size, len(out) + 1)]


def task_xml(name: str, command: str) -> bytes:
    """Windows stores task definitions as UTF-16LE XML with a BOM."""
    xml = (
        '<?xml version="1.0" encoding="UTF-16"?>\r\n'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
        "  <RegistrationInfo>\r\n"
        f"    <Description>{BANNER}</Description>\r\n"
        f"    <URI>\\{name}</URI>\r\n"
        "  </RegistrationInfo>\r\n"
        "  <Actions Context=\"Author\">\r\n"
        f"    <Exec><Command>{command}</Command></Exec>\r\n"
        "  </Actions>\r\n"
        "</Task>\r\n"
    )
    return b"\xff\xfe" + xml.encode("utf-16-le")


SQLITE = b"SQLite format 3\0"
JOURNAL = bytes.fromhex("d9d505f920a163d7")
WAL = bytes.fromhex("377f0682002de218")

FILES: dict[str, bytes] = {
    # hives (system)
    "Windows/System32/config/SYSTEM": body(b"regf", "hive SYSTEM", 512),
    "Windows/System32/config/SYSTEM.LOG1": body(b"regf", "transaction log SYSTEM.LOG1", 256),
    "Windows/System32/config/SOFTWARE": body(b"regf", "hive SOFTWARE", 512),
    "Windows/System32/config/SAM": body(b"regf", "hive SAM", 384),
    "Windows/System32/config/SECURITY": body(b"regf", "hive SECURITY", 384),
    "Windows/System32/config/DEFAULT": body(b"regf", "hive DEFAULT", 384),
    # event logs
    "Windows/System32/winevt/Logs/Security.evtx": body(b"ElfFile\0", "event log Security", 512),
    "Windows/System32/winevt/Logs/System.evtx": body(b"ElfFile\0", "event log System", 512),
    "Windows/System32/winevt/Logs/Application.evtx": body(b"ElfFile\0", "event log Application", 512),
    # prefetch: Windows 10/11 compressed (MAM\x04) and uncompressed (version 30, SCCA)
    "Windows/Prefetch/CMD.EXE-0BD30981.pf": body(b"MAM\x04", "prefetch CMD.EXE (compressed form)", 320),
    "Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf": body(b"\x1e\0\0\0SCCA", "prefetch NOTEPAD.EXE (uncompressed form)", 320),
    # scheduled tasks
    "Windows/System32/Tasks/RakvorSampleUpdater": task_xml("RakvorSampleUpdater", "C:\\Sample\\updater.exe"),
    "Windows/System32/Tasks/RakvorSample/DailyCheck": task_xml("RakvorSample\\DailyCheck", "C:\\Sample\\check.exe"),
    # per-user hives
    "Users/ana.ruiz/NTUSER.DAT": body(b"regf", "user hive NTUSER.DAT (ana.ruiz, synthetic)", 384),
    "Users/ana.ruiz/AppData/Local/Microsoft/Windows/UsrClass.dat": body(b"regf", "user hive UsrClass.dat (ana.ruiz, synthetic)", 384),
    "Users/ben.test/NTUSER.DAT": body(b"regf", "user hive NTUSER.DAT (ben.test, synthetic)", 384),
    "Users/ben.test/AppData/Local/Microsoft/Windows/UsrClass.dat": body(b"regf", "user hive UsrClass.dat (ben.test, synthetic)", 384),
    # browsers
    "Users/ana.ruiz/AppData/Local/Microsoft/Edge/User Data/Default/History": body(SQLITE, "Edge History (synthetic)", 512),
    "Users/ana.ruiz/AppData/Local/Microsoft/Edge/User Data/Default/History-journal": body(JOURNAL, "Edge History journal", 256),
    "Users/ben.test/AppData/Local/Google/Chrome/User Data/Default/History": body(SQLITE, "Chrome History (synthetic)", 512),
    "Users/ben.test/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2z3.default-release/places.sqlite": body(SQLITE, "Firefox places (synthetic)", 512),
    "Users/ben.test/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2z3.default-release/places.sqlite-wal": body(WAL, "Firefox places WAL", 256),
}


def main() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for rel, data in FILES.items():
        p = ROOT / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    total = sum(len(d) for d in FILES.values())
    print(f"{len(FILES)} files, {total} bytes in {ROOT}")


if __name__ == "__main__":
    main()

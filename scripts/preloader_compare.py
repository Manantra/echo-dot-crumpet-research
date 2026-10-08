#!/usr/bin/env python3
"""Read-only comparison of two Crumpet preloader binary files."""
import argparse
import hashlib
import re
from pathlib import Path

MARKERS = (
    b"check_part_overlapped done",
    b"check_part_overlapped",
    b"[ANTI-ROLLBACK]",
    b"DA_IMAGE_SIG_VERIFY_FAIL",
    b"[BLDR] Build Time:",
    b"MT65xx Preloader",
    b"USB CDC ACM for preloader",
)
REPORTED_2023_SHA256 = "d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b"

def inspect(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path,
        "data": data,
        "sha": hashlib.sha256(data).hexdigest(),
        "stamps": sorted(set(s.decode("ascii") for s in re.findall(rb"20\d{6}_\d{6}", data))),
        "markers": {m.decode("ascii"): data.find(m) for m in MARKERS},
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("older", type=Path)
    p.add_argument("newer", type=Path)
    args = p.parse_args()
    a, b = inspect(args.older), inspect(args.newer)
    for item in (a, b):
        print("\n", item["path"], f"({len(item['data'])} bytes)")
        print("SHA-256:", item["sha"])
        print("Matches reported 2023 hash:", item["sha"] == REPORTED_2023_SHA256)
        print("Candidate build stamps:", item["stamps"] or "not found")
        for marker, offset in item["markers"].items():
            print(f"  {marker}: {hex(offset) if offset >= 0 else 'NOT FOUND'}")
    # Equal content aligned to the same 4KiB boundary is only a weak signal.
    block = 4096
    ka = {hashlib.sha256(a["data"][i:i+block]).digest() for i in range(0, len(a["data"]), block)}
    kb = {hashlib.sha256(b["data"][i:i+block]).digest() for i in range(0, len(b["data"]), block)}
    print("\nShared 4KiB block fingerprints:", len(ka & kb))
    print("WARNING: file wrappers, relocation, absent diagnostic strings and alignment may obscure actual code differences.")
    print("This is NOT a function-level disassembly or vulnerability verdict. Never flash based on this output.")

if __name__ == "__main__":
    main()

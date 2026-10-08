#!/usr/bin/env python3
"""Static ARM entry and NAND-capability comparison of bundled MTKClient DAs.

Input: a *local* MTKClient Loader directory. Reads DA binaries but never
exports them, patches them, runs ARM code, uploads anything, or accesses USB.
The capability markers are evidence of strings, not proof that a driver works.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory

MARKERS = {
    "NAND diagnostics": (b"nand ", b"NAND ", b"nandx_", b"device_nand."),
    "Bad-block management": (b"[BMT]", b"bmt_exist", b"bmt data"),
    "DRAM initialization": (b"init dram pass", b"DRAM_FAIL"),
}


def inspect_region(data, region):
    begin, length = region["file_offset"], region["bytes"]
    if length < 0x40 or begin + length > len(data):
        raise ValueError("DA stage region too short or out of bounds")
    raw = memoryview(data)[begin:begin + length]
    signature = region["signature_bytes"]
    if signature >= length:
        raise ValueError("DA signature length greater than region")
    body = bytes(raw[:-signature] if signature else raw)
    word = struct.unpack_from("<I", body)[0]
    if word & 0xff000000 != 0xea000000:
        raise ValueError("Expected ARM unconditional B at DA entry")
    imm24 = word & 0xffffff
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    target = region["address"] + 8 + imm24 * 4
    if not region["address"] <= target < region["address"] + len(body):
        raise ValueError("DA initial ARM branch points outside stage code")
    counts = {label: sum(body.count(marker) for marker in needles)
              for label, needles in MARKERS.items()}
    return {
        "entry": target, "region_sha256": hashlib.sha256(raw).hexdigest(),
        "effective_len": len(body), "markers": counts, "prefix": body[:256],
    }


def inspect_directory(directory, hw=0x8167):
    all_entries, retained, hidden = scan_directory(directory, hw)
    results = []
    for entry in all_entries:
        path = directory / entry["filename"]
        raw = path.read_bytes()
        if len(entry["regions"]) < 3:
            raise ValueError("Expected at least three DA regions")
        stage1 = inspect_region(raw, entry["regions"][1])
        stage2 = inspect_region(raw, entry["regions"][2])
        results.append({"filename": entry["filename"],
                        "loader_sha256": entry["file_sha256"],
                        "stage1": stage1, "stage2": stage2,
                        "target": entry["regions"][2]["address"]})
    return results, [entry["filename"] for entry in hidden]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loader_directory", type=Path)
    args = parser.parse_args()
    results, hidden = inspect_directory(args.loader_directory)
    for info in results:
        print("DA:", info["filename"], "SHA-256:", info["loader_sha256"])
        for stage in ("stage1", "stage2"):
            r = info[stage]
            print(f"  {stage}: ARM-entry={r['entry']:#010x}, "
                  f"body={r['effective_len']} bytes, SHA256={r['region_sha256']}")
            print("   marker counts:", r["markers"])
    if len(results) == 2:
        a, b = (r["stage2"]["prefix"] for r in results)
        prefix_len = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y),
                          min(len(a), len(b)))
        print("Common Stage-2 entry prefix:", prefix_len, "bytes")
    print("Default loader-selection alternatives suppressed:", hidden)
    print("NAND strings and a valid ARM entry do NOT establish device compatibility.")
    print("No firmware exported, no USB access, no hardware modifications.")


if __name__ == "__main__":
    main()

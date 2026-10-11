#!/usr/bin/env python3
"""Read-only, streaming comparison of two EXISTING raw-NAND captures.

For the HISTORICAL Crumpet MX30LF4G28AD geometry only: 131072 pages x
4352 physical bytes. Requires full captures unless --allow-partial is explicit.
Never contacts hardware, changes files or claims ECC/BBT or restore validity.

Default layout 'opaque' avoids assuming where NAND spare/ECC bytes physically
reside. Opt-in layouts are hypotheses chosen by the researcher.
"""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from check_crumpet_raw_nand_dump_size import (
    DATA_BYTES, DATA_PLUS_OOB_SIZE, RAW_PAGE_BYTES, TOTAL_PAGES,
    PAGES_PER_BLOCK,
)

FOUR_CHUNK_MAIN = 1024
FOUR_CHUNK_AUX = 64
FOUR_CHUNK_SIZE = FOUR_CHUNK_MAIN + FOUR_CHUNK_AUX

def open_existing_regular(path):
    """Open existing regular files only, never devices, FIFOs or symlinks."""
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Input must be an existing regular file (no symlink/device)")
    # O_NONBLOCK avoids hanging on accidental nonregular input after a race.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    fi = os.fdopen(fd, "rb")
    opened = os.fstat(fi.fileno())
    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        fi.close()
        raise ValueError("Input changed during open or is not regular")
    return fi, opened

def classify_differences(first, second, layout):
    """The caller chooses an ASSUMED layout; never infer a layout from file size."""
    if len(first) != RAW_PAGE_BYTES or len(second) != RAW_PAGE_BYTES:
        raise ValueError("Physical page length mismatch")
    if layout == "opaque":
        return None, None
    if layout == "contiguous":
        return first[:DATA_BYTES] != second[:DATA_BYTES], first[DATA_BYTES:] != second[DATA_BYTES:]
    if layout == "interleaved-four":
        payload_diff = aux_diff = False
        for start in range(0, RAW_PAGE_BYTES, FOUR_CHUNK_SIZE):
            payload_diff |= (first[start:start+FOUR_CHUNK_MAIN] !=
                             second[start:start+FOUR_CHUNK_MAIN])
            aux_diff |= (first[start+FOUR_CHUNK_MAIN:start+FOUR_CHUNK_SIZE] !=
                         second[start+FOUR_CHUNK_MAIN:start+FOUR_CHUNK_SIZE])
        return bool(payload_diff), bool(aux_diff)
    raise ValueError("Unknown NAND readback layout")

def validate_size(size, allow_partial):
    if size <= 0 or size > DATA_PLUS_OOB_SIZE:
        raise ValueError("Empty or over-capacity raw NAND capture")
    if size % RAW_PAGE_BYTES:
        raise ValueError("Truncated page: file size is not multiple of 4352")
    if size != DATA_PLUS_OOB_SIZE and not allow_partial:
        raise ValueError("Not full historical NAND capture; --allow-partial required")
    return size // RAW_PAGE_BYTES

def compare_streams(left, right, expected_size, layout="opaque", allow_partial=False,
                    example_limit=12):
    """Only bytes are compared; input streams must already be regular files."""
    pages = validate_size(expected_size, allow_partial)
    count = {"exact_pages": 0, "different_pages": 0,
             "payload_only_differences": 0, "auxiliary_only_differences": 0,
             "payload_and_auxiliary_differences": 0}
    h1, h2 = hashlib.sha256(), hashlib.sha256()
    examples, blocks = [], set()
    for index in range(pages):
        p1 = left.read(RAW_PAGE_BYTES)
        p2 = right.read(RAW_PAGE_BYTES)
        if len(p1) != RAW_PAGE_BYTES or len(p2) != RAW_PAGE_BYTES:
            raise ValueError("Capture changed or ended unexpectedly")
        h1.update(p1)
        h2.update(p2)
        if p1 == p2:
            count["exact_pages"] += 1
            continue
        count["different_pages"] += 1
        blocks.add(index // PAGES_PER_BLOCK)
        if len(examples) < example_limit:
            examples.append(index)
        payload, aux = classify_differences(p1, p2, layout)
        if layout != "opaque":
            if payload and aux:
                count["payload_and_auxiliary_differences"] += 1
            elif payload:
                count["payload_only_differences"] += 1
            elif aux:
                count["auxiliary_only_differences"] += 1
            else:
                raise AssertionError("Unclassified page mismatch")
    if left.read(1) or right.read(1):
        raise ValueError("File grew unexpectedly during comparison")
    return {
        "scope": "full_historical_geometry" if pages == TOTAL_PAGES else "partial_only",
        "layout_assumption": layout,
        "layout_confirmed_from_hardware": False,
        "bytes_per_capture": expected_size,
        "pages_compared": pages,
        "capture_1_sha256": h1.hexdigest(),
        "capture_2_sha256": h2.hexdigest(),
        **count,
        "different_erase_blocks": len(blocks),
        "first_different_pages": examples,
        "raw_bytes_match_exactly": count["different_pages"] == 0,
        "oob_structure_validated": False,
        "ecc_validated": False,
        "bad_block_table_validated": False,
        "writeback_or_cold_boot_validated": False,
        "safe_to_restore": False,
    }

def compare_files(first, second, layout="opaque", allow_partial=False):
    with open_existing_regular(first)[0] as f1, open_existing_regular(second)[0] as f2:
        a, b = os.fstat(f1.fileno()), os.fstat(f2.fileno())
        if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
            raise ValueError("Two independent capture files required (same inode)")
        if a.st_size != b.st_size:
            raise ValueError("Capture lengths differ")
        report = compare_streams(f1, f2, a.st_size, layout, allow_partial)
        a2, b2 = os.fstat(f1.fileno()), os.fstat(f2.fileno())
        if (a.st_size, a.st_mtime_ns) != (a2.st_size, a2.st_mtime_ns) or (
                b.st_size, b.st_mtime_ns) != (b2.st_size, b2.st_mtime_ns):
            raise ValueError("Input file mutated during comparison")
        return report

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_a", type=Path, help="Already captured raw main+spare bytes")
    ap.add_argument("capture_b", type=Path, help="Second independent captured file")
    ap.add_argument("--allow-partial", action="store_true",
                    help="Permit intentionally incomplete images; never mark as full")
    ap.add_argument("--layout", choices=("opaque", "interleaved-four", "contiguous"),
                    default="opaque", help="Assumed byte layout; never detected automatically")
    args = ap.parse_args()
    print(json.dumps(compare_files(args.capture_a, args.capture_b, args.layout,
                                   args.allow_partial), indent=2, sort_keys=True))

if __name__ == "__main__":
    main()

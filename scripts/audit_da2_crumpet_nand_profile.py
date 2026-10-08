#!/usr/bin/env python3
"""Identify a SHA-pinned Macronix raw-NAND chip profile inside MT8167 DA2.

Reads the bundled stock MTKClient DA containers off disk. Never exports DA
bytes, executes ARM code, uploads a DA or accesses USB/NAND hardware.

Source provenance: bkerler/mtkclient commit cd25cf9.
A table record is recognized only when a valid DA2-base-relative name
pointer is immediately followed by the six historical Macronix NAND ID
bytes, the correct ID length, and matching main/OOB page-size fields.
This proves a binary lookup-table entry, NOT working device access.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory

EXPECTED = {
    "MTK_DA_V5.bin":
        "aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f",
    "MTK_AllInOne_DA_mt6590.bin":
        "49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64",
}
MODEL = b"MX30LF4G28AD\x00"
ID = bytes.fromhex("c2 dc 90 a2 57 03")
CHIP_PAGE_BYTES = 0x1000
CHIP_OOB_BYTES = 0x100
LOAD_BASE = 0x40000000


def find_chip_profiles(body, load_base=LOAD_BASE):
    """Return concrete name-pointer+ID associations in a DA2 binary.

    This does not interpret unknown controller configuration flags, the
    semantics of other table fields, or data-structure boundaries globally.
    """
    candidates = []
    off = 0
    while True:
        name_at = body.find(MODEL, off)
        if name_at < 0:
            break
        if name_at + len(MODEL) > len(body):
            break
        expected_ptr = struct.pack("<I", load_base + name_at)
        possible = 0
        while True:
            rec = body.find(expected_ptr + ID, possible)
            if rec < 0:
                break
            possible = rec + 1
            # Data layout: 4-byte name pointer, up to 8 ID bytes, 32-bit
            # ID length and subsequent unsigned hardware parameters.
            if rec + 0x24 > len(body):
                continue
            id_length = struct.unpack_from("<I", body, rec + 0xC)[0]
            page, oob = struct.unpack_from("<II", body, rec + 0x18)
            if id_length != len(ID):
                continue
            candidates.append({
                "name_at_offset": name_at,
                "record_offset": rec,
                "name_address": load_base + name_at,
                "nand_id": ID.hex(" "),
                "id_length": id_length,
                "field_0x10_raw": struct.unpack_from("<I", body, rec + 0x10)[0],
                "field_0x14_raw": struct.unpack_from("<I", body, rec + 0x14)[0],
                "page_bytes_at_0x18": page,
                "oob_bytes_at_0x1c": oob,
                "page_geometry_matches_reported_chip":
                    page == CHIP_PAGE_BYTES and oob == CHIP_OOB_BYTES,
            })
        off = name_at + 1
    return candidates


def inspect_loader_directory(directory):
    all_entries, _, _ = scan_directory(directory)
    result = []
    for entry in all_entries:
        name = entry["filename"]
        if name not in EXPECTED:
            continue
        if entry["file_sha256"] != EXPECTED[name]:
            raise ValueError(f"{name}: pinned MTKClient loader SHA-256 changed")
        region = entry["regions"][2]
        if region["address"] != LOAD_BASE:
            raise ValueError("Unexpected DA2 DRAM base address")
        all_data = (directory / name).read_bytes()
        offset, size = region["file_offset"], region["bytes"]
        signature = region["signature_bytes"]
        if not 0 < signature < size or offset + size > len(all_data):
            raise ValueError("DA2 region signature or length invalid")
        body = all_data[offset:offset + size - signature]
        profiles = find_chip_profiles(body, LOAD_BASE)
        result.append({
            "filename": name,
            "container_sha256": entry["file_sha256"],
            "da2_body_sha256": hashlib.sha256(body).hexdigest(),
            "matching_records": profiles,
        })
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader_dir", type=Path,
                   help="Local MTKClient mt8167 stock Loader directory")
    args = p.parse_args()
    records = inspect_loader_directory(args.loader_dir)
    if not records:
        raise SystemExit("No pinned original MT8167 DA container found")
    for item in records:
        print("DA container:", item["filename"],
              "SHA-256:", item["container_sha256"])
        print("DA2 original body SHA-256:", item["da2_body_sha256"])
        for rec in item["matching_records"]:
            print("  MATCH: MX30LF4G28AD name at", hex(rec["name_at_offset"]),
                  "profile at", hex(rec["record_offset"]),
                  "name pointer", hex(rec["name_address"]))
            print("  ID:", rec["nand_id"], "length:", rec["id_length"],
                  "page bytes:", rec["page_bytes_at_0x18"],
                  "OOB bytes:", rec["oob_bytes_at_0x1c"])
            print("  Page/OOB geometry matches historical chip:",
                  rec["page_geometry_matches_reported_chip"])
            print("  Additional fields preserved WITHOUT guessed meaning:",
                  hex(rec["field_0x10_raw"]), hex(rec["field_0x14_raw"]))
        if not item["matching_records"]:
            print("  No exact model-name pointer + historical NAND ID record.")
    print("A DA2 chip table does NOT demonstrate successful Stage-2 execution, "
          "NAND readback, or device compatibility on modern board revisions.")
    print("No DA bytes exported; no flash or USB operation performed.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read-only MediaTek Crumpet GFH security metadata comparison.

Accepts only ORIGINAL local 2019/2021/2025 Crumpet preloader images with
known full SHA-256. This tool does not verify signatures or anti-rollback
policy. It does not write images, produce patches or access physical devices.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from disassemble_preloader import locate_image

KNOWN_IMAGES = {
    "e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637": "public-2019",
    "a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5": "official-2021",
    "837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a": "official-2025-nov",
}
EXPECTED_CHAIN = (0, 1, 7, 2, 8, 3)
TYPES = {0: "FILE_INFO", 1: "BL_INFO", 7: "BROM_CFG",
         2: "ANTI_CLONE", 8: "BROM_SEC_CFG", 3: "BL_SEC_KEY"}


def parse_chain(data, require_known=True):
    digest = hashlib.sha256(data).hexdigest()
    if require_known and digest not in KNOWN_IMAGES:
        raise ValueError("Unpinned original image SHA-256; no claim about this build")
    entry, load = locate_image(data)
    start = entry - 0x300
    offset = start
    records = []
    while offset + 8 <= entry:
        magic, size, typ = struct.unpack_from("<IHH", data, offset)
        if magic & 0x00FFFFFF != 0x004D4D4D:
            break
        if magic >> 24 != 1 or size < 8 or offset + size > entry:
            raise ValueError("Unexpected GFH marker, version or bounds")
        body = data[offset:offset + size]
        records.append({
            "type": typ, "size": size,
            "sha256": hashlib.sha256(body).hexdigest(),
            "relative_offset": offset - start,
        })
        offset += size
    if offset != entry:
        raise ValueError("GFH records do not end exactly at first ARM entry")
    if tuple(r["type"] for r in records) != EXPECTED_CHAIN:
        raise ValueError("Unexpected Crumpet GFH record type sequence")
    if records[0]["size"] != 0x38:
        raise ValueError("Unexpected GFH FILE_INFO size")
    info = struct.unpack_from("<IHH12sIHBBIIIIIII", data, start)
    (_, _, _, name, file_ver, file_type, flash_dev, sig_type,
     base, file_len, max_size, content_offset, sig_len,
     jump_offset, attrs) = info
    if name.rstrip(b"\x00") != b"FILE_INFO":
        raise ValueError("Bad GFH FILE_INFO name")
    if base != load or jump_offset != 0x300 or content_offset != 0x300:
        raise ValueError("Unexpected code-start/base relationship")
    if not (0 < sig_len < file_len <= max_size):
        raise ValueError("Unexpected GFH signature/image length")
    return {
        "image_id": KNOWN_IMAGES.get(digest, "synthetic-unpinned"),
        "full_sha256": digest, "stored_gfh_offset": start,
        "file_version": file_ver, "file_type": file_type,
        "flash_device": flash_dev, "signature_type": sig_type,
        "signature_size": sig_len, "code_load_address": base,
        "gfh_image_length": file_len, "max_image_size": max_size,
        "file_info_attributes": attrs,
        "records": records,
    }


def compare_chains(results):
    if len(results) < 2:
        raise ValueError("Two or more original images required")
    records = [r["records"] for r in results]
    return [
        {
            "type": records[0][idx]["type"],
            "name": TYPES[records[0][idx]["type"]],
            "byte_identical_across_all": len({
                r[idx]["sha256"] for r in records}) == 1,
            "hashes": [r[idx]["sha256"] for r in records],
        }
        for idx in range(len(EXPECTED_CHAIN))
    ]


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("preloader_images", type=Path, nargs="+")
    args = arg.parse_args()
    analyses = [parse_chain(p.read_bytes()) for p in args.preloader_images]
    for path, row in zip(args.preloader_images, analyses):
        print(path.name, row["image_id"], "full SHA-256", row["full_sha256"])
        for key in ("stored_gfh_offset", "file_version", "file_type",
                    "flash_device", "signature_type", "signature_size",
                    "gfh_image_length", "max_image_size",
                    "file_info_attributes"):
            print("  ", key, row[key])
    if len(analyses) > 1:
        for item in compare_chains(analyses):
            print(f"GFH {item['name']}: bytes IDENTICAL across all checked images:",
                  item["byte_identical_across_all"])
    print("Identical metadata does NOT prove an older image is accepted by BROM, "
          "that signatures verify, or that hardware rollback policy allows downgrade.")
    print("No device access or modifications.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare manifest-verified Crumpet OTA preloader image bytes WITHOUT saving images.

Uses official Amazon CDN HTTPS Range fetches, validates both OTA-operation
and uncompressed-partition SHA-256 digests, then reports differences in the
raw-NAND prefix vs MediaTek GFH-anchored image. No firmware redistribution,
no USB/device access, no write or bootloader modification.
"""
import argparse
import hashlib
import lzma
import struct
from urllib.parse import urlparse

import ota_inventory as ota
from remote_ota_probe import CDN_HOST, PREFIX_SIZE, MAX_OP_SIZE, fetch_range

GFH_MARKER = b"MMM\x01"


def extract_partition(url, partition_name="brhgptpl_0"):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != CDN_HOST:
        raise ValueError("Expected an official Amazon CDN HTTPS URL")
    if not partition_name.startswith("brhgptpl_"):
        raise ValueError("Only Crumpet preloader partitions are supported")
    hdr = fetch_range(url, 0, PREFIX_SIZE - 1)
    if hdr[:4] != b"PK\x03\x04":
        raise ValueError("Missing ZIP local-file header")
    filename_length, extra_length = struct.unpack_from("<HH", hdr, 26)
    payload_offset = 30 + filename_length + extra_length
    if hdr[30:30 + filename_length] != b"payload.bin":
        raise ValueError("Expected uncompressed payload.bin first")
    if struct.unpack_from("<H", hdr, 8)[0] != 0:
        raise ValueError("Compressed ZIP payload.bin not supported")
    if hdr[payload_offset:payload_offset + 4] != b"CrAU":
        raise ValueError("Missing CrAU payload")
    major, manifest_length, signature_length = struct.unpack_from(
        ">QQI", hdr, payload_offset + 4
    )
    if major != 2 or manifest_length > 32768:
        raise ValueError("Invalid update manifest")
    begin = payload_offset + 24
    if begin + manifest_length > len(hdr):
        raise ValueError("Manifest does not fit the guarded first range")
    manifest = hdr[begin:begin + manifest_length]
    blocksize = ota.first(manifest, 3)
    partition = next((p for p in ota.values(manifest, 13)
                      if ota.first(p, 1).decode() == partition_name), None)
    if partition is None:
        raise ValueError(f"Missing {partition_name} in OTA manifest")
    info = ota.first(partition, 7)
    if info is None:
        raise ValueError("Partition lacks expected image hash")
    operation_list = ota.values(partition, 8)
    if len(operation_list) != 1:
        raise ValueError("Expected one XZ replace operation")
    op = operation_list[0]
    kind, relative_offset, length = (ota.first(op, n) for n in (1, 2, 3))
    if kind != 8 or not 0 < length <= MAX_OP_SIZE:
        raise ValueError("Not a bounded REPLACE_XZ operation")
    extent = ota.values(op, 6)
    declared_length = ota.first(info, 1)
    if not (len(extent) == 1 and ota.first(extent[0], 1) == 0
            and ota.first(extent[0], 2) * blocksize == declared_length):
        raise ValueError("Unexpected output partition extent")
    absolute_offset = begin + manifest_length + signature_length + relative_offset
    compressed = fetch_range(url, absolute_offset, absolute_offset + length - 1)
    if hashlib.sha256(compressed).digest() != ota.first(op, 8):
        raise ValueError("Compressed operation SHA256 failed")
    binary = lzma.decompress(compressed)
    if (len(binary) != declared_length or
            hashlib.sha256(binary).digest() != ota.first(info, 2)):
        raise ValueError("Uncompressed partition SHA256 failed")
    return binary


def summarize_pair(first, second):
    if len(first) != len(second):
        raise ValueError("Cannot byte-compare different-sized partitions")
    a = first.find(GFH_MARKER)
    b = second.find(GFH_MARKER)
    if a < 0 or a != b:
        raise ValueError("Missing or differently located MediaTek GFH anchor")
    diffs = [index for index, (v, w) in enumerate(zip(first, second)) if v != w]
    prefix = [index for index in diffs if index < a]
    suffix = [index for index in diffs if index >= a]
    return {
        "total": len(first),
        "gfh_offset": a,
        "full_sha256_a": hashlib.sha256(first).hexdigest(),
        "full_sha256_b": hashlib.sha256(second).hexdigest(),
        "gfh_suffix_sha256_a": hashlib.sha256(first[a:]).hexdigest(),
        "gfh_suffix_sha256_b": hashlib.sha256(second[a:]).hexdigest(),
        "prefix_changed_bytes": len(prefix),
        "suffix_changed_bytes": len(suffix),
        "first_difference": diffs[0] if diffs else None,
        "last_difference": diffs[-1] if diffs else None,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("older_ota_url", help="HTTPS official Amazon Crumpet OTA URL")
    p.add_argument("newer_ota_url", help="HTTPS official Amazon Crumpet OTA URL")
    p.add_argument("--partition", default="brhgptpl_0",
                   choices=[f"brhgptpl_{i}" for i in range(4)])
    a = p.parse_args()
    first = extract_partition(a.older_ota_url, a.partition)
    second = extract_partition(a.newer_ota_url, a.partition)
    summary = summarize_pair(first, second)
    print("Manifest-verified OTA Crumpet raw preloader partition comparison")
    print("Partition:", a.partition, "bytes:", summary["total"])
    for name, value in summary.items():
        if name == "total":
            continue
        if isinstance(value, int) and ("offset" in name or "difference" in name):
            print(name, hex(value))
        else:
            print(name, value)
    print("MEDIA TEK GFH-ANCHORED REGION IDENTICAL:",
          summary["suffix_changed_bytes"] == 0)
    print("A changed raw partition SHA does NOT alone prove changed preloader code.")
    print("No images saved; Amazon OTA package signature NOT authenticated.")


if __name__ == "__main__":
    main()

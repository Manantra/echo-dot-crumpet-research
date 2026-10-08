#!/usr/bin/env python3
"""Inspect hashes of Crumpet preloader and optionally LK via official Amazon OTA HTTPS.

Uses HTTP Range to retrieve only the ZIP/payload manifest and compressed
brhgptpl_* (and optionally LK) operations. No images are written to disk,
and no hardware is accessed. Manifest hashes are checked, not the OTA signature.
"""
import argparse
import hashlib
import lzma
import re
import struct
import urllib.request
from urllib.parse import urlparse

import ota_inventory as ota

CDN_HOST = "d1s31zyz7dcc2d.cloudfront.net"
PREFIX_SIZE = 65536
MAX_OP_SIZE = 4 * 1024 * 1024


def fetch_range(url, start, end):
    if end < start or end - start + 1 > MAX_OP_SIZE:
        raise ValueError("Invalid HTTP range")
    request = urllib.request.Request(
        url, headers={"Range": f"bytes={start}-{end}",
                      "User-Agent": "Crumpet-ReadOnly-Research/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 206:
            raise ValueError("Server ignored HTTP Range; refusing full download")
        result = response.read(end - start + 2)
    if len(result) != end - start + 1:
        raise ValueError("Unexpected range length")
    return result


def probe(url, include_lk=False):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != CDN_HOST:
        raise ValueError(f"Only official Amazon CDN HTTPS URLs ({CDN_HOST}) accepted")
    header = fetch_range(url, 0, PREFIX_SIZE - 1)
    if header[:4] != b"PK\x03\x04":
        raise ValueError("Not a ZIP local file header")
    method = struct.unpack_from("<H", header, 8)[0]
    name_len, extra_len = struct.unpack_from("<HH", header, 26)
    start = 30 + name_len + extra_len
    if header[30:30 + name_len] != b"payload.bin" or method != 0:
        raise ValueError("Expected uncompressed payload.bin as first ZIP entry")
    if header[start:start + 4] != b"CrAU":
        raise ValueError("Missing CrAU magic")
    major, manifest_length, signature_length = struct.unpack_from(">QQI", header, start + 4)
    if major != 2 or manifest_length > 32768:
        raise ValueError("Unsupported update_engine payload")
    meta_end = start + 24 + manifest_length
    if meta_end > len(header):
        raise ValueError("Manifest larger than the first HTTP range")
    manifest = header[start + 24:meta_end]
    block_size = ota.first(manifest, 3)
    blob_base = meta_end + signature_length
    print(f"Android OTA v{major}; manifest={manifest_length}; blocksize={block_size}")
    parts = ota.values(manifest, 13)
    print("Partition names:", ", ".join(ota.first(p, 1).decode() for p in parts))
    findings = []
    for partition in parts:
        name = ota.first(partition, 1).decode()
        if not name.startswith("brhgptpl_") and not (include_lk and name == "lk"):
            continue
        info = ota.first(partition, 7)
        expected_size = ota.first(info, 1)
        expected_hash = ota.first(info, 2)
        operations = ota.values(partition, 8)
        if len(operations) != 1:
            raise ValueError(f"Expected one partition operation for {name}")
        operation = operations[0]
        kind, relative, length = (ota.first(operation, n) for n in (1, 2, 3))
        if kind != 8 or not isinstance(length, int) or length > MAX_OP_SIZE:
            raise ValueError(f"Unsupported partition compression for {name}")
        extents = ota.values(operation, 6)
        if (len(extents) != 1 or ota.first(extents[0], 1) != 0 or
                ota.first(extents[0], 2) * block_size != expected_size):
            raise ValueError(f"Unsupported partition destination layout for {name}")
        blob = fetch_range(url, blob_base + relative,
                           blob_base + relative + length - 1)
        if hashlib.sha256(blob).digest() != ota.first(operation, 8):
            raise ValueError(f"Compressed data SHA-256 mismatch: {name}")
        raw = lzma.decompress(blob)
        if len(raw) != expected_size or hashlib.sha256(raw).digest() != expected_hash:
            raise ValueError(f"Partition SHA-256 mismatch: {name}")
        builds = sorted(set(s.decode() for s in re.findall(rb"20\d{6}_\d{6}", raw)))
        marker = raw.find(b"check_part_overlapped done")
        row = (name, expected_size, expected_hash.hex(), builds, marker)
        findings.append(row)
        if name == "lk":
            tokens = (b"flash:unlock", b"flash:otucert",
                      b"flash:otucode", b"amzn_verify_onetime_unlock_code",
                      b"the command you input is restricted on locked hw")
            summary = ",".join(f"{t.decode()}={t in raw}" for t in tokens)
            print(f"VERIFIED LK: SHA-256={row[2]} build={builds} {summary}")
        else:
            print(f"VERIFIED {name}: SHA-256={row[2]} build={builds} "
                  f"overlap_string={'missing' if marker < 0 else hex(marker)}")
    print("No images saved. OTA package signature was NOT independently verified.")
    return findings


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("url", help=f"Official HTTPS URL on {CDN_HOST}")
    p.add_argument("--include-lk", action="store_true",
                   help="Also retrieve and verify the LK image in memory; no output firmware files")
    args = p.parse_args()
    probe(args.url, include_lk=args.include_lk)


if __name__ == "__main__":
    main()

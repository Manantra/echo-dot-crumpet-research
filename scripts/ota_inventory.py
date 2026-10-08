#!/usr/bin/env python3
"""Inspect Android A/B OTA manifests; optionally verify Crumpet preloader images in RAM.

Read-only: never writes extracted firmware or communicates with a device.
Only Python standard-library modules are used.
"""
import argparse
import hashlib
import lzma
import re
import struct
import zipfile
from pathlib import Path

MAX_MANIFEST = 4 * 1024 * 1024
MAX_PRELOADER = 4 * 1024 * 1024
OP_REPLACE = 0
OP_REPLACE_XZ = 8


def fields(data):
    """Read only the varint, fixed32/64 and length-delimited protobuf wire types."""
    at = 0

    def varint():
        nonlocal at
        number = 0
        for shift in range(0, 70, 7):
            if at >= len(data):
                raise ValueError("Truncated protobuf varint")
            byte = data[at]
            at += 1
            number |= (byte & 127) << shift
            if byte < 128:
                return number
        raise ValueError("Oversized protobuf varint")

    while at < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError("Invalid field number 0")
        if wire == 0:
            value = varint()
        elif wire in (1, 5):
            width = 8 if wire == 1 else 4
            if at + width > len(data):
                raise ValueError("Truncated protobuf fixed value")
            value = data[at:at + width]
            at += width
        elif wire == 2:
            width = varint()
            if at + width > len(data):
                raise ValueError("Truncated protobuf bytes")
            value = data[at:at + width]
            at += width
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire}")
        yield number, wire, value


def values(data, number):
    return [value for field, _, value in fields(data) if field == number]


def first(data, number, default=None):
    return next((value for field, _, value in fields(data) if field == number), default)


def parse_manifest(z):
    with z.open("payload.bin") as payload:
        header = payload.read(24)
        if len(header) != 24 or header[:4] != b"CrAU":
            raise ValueError("Not an Android CrAU payload")
        major, manifest_size, sig_size = struct.unpack(">QQI", header[4:24])
        if major != 2 or manifest_size > MAX_MANIFEST:
            raise ValueError("Unexpected payload version or manifest size")
        manifest = payload.read(manifest_size)
        if len(manifest) != manifest_size:
            raise ValueError("Truncated manifest")
    parsed = []
    for part in values(manifest, 13):
        name = first(part, 1)
        info = first(part, 7)
        if not isinstance(name, bytes) or not isinstance(info, bytes):
            raise ValueError("Malformed PartitionUpdate")
        size, digest = first(info, 1), first(info, 2)
        ops = values(part, 8)
        parsed.append(dict(name=name.decode("utf-8"), size=size,
                           digest=digest, operations=ops))
    return parsed, 24 + manifest_size + sig_size, first(manifest, 3), major


def verify_brhgptpl(z, parts, blob_start, block_size):
    with z.open("payload.bin") as stream:
        # Keep stream movement forward to avoid unnecessarily repeating reads.
        candidates = [p for p in parts if p["name"].startswith("brhgptpl_")]
        candidates.sort(key=lambda p: first(p["operations"][0], 2, 0))
        for part in candidates:
            size, expected = part["size"], part["digest"]
            if not isinstance(size, int) or not 0 < size <= MAX_PRELOADER:
                raise ValueError(f"Unsafe or invalid partition size: {part['name']}")
            data = bytearray(size)
            touched = set()
            for operation in part["operations"]:
                kind, offset, count = (first(operation, i) for i in (1, 2, 3))
                digest = first(operation, 8)
                if kind not in (OP_REPLACE, OP_REPLACE_XZ):
                    raise ValueError(f"Unsupported op {kind} in {part['name']}")
                if not all(isinstance(v, int) and v >= 0 for v in (offset, count)):
                    raise ValueError("Invalid payload operation")
                if count > MAX_PRELOADER:
                    raise ValueError("Oversized compressed operation")
                stream.seek(blob_start + offset)
                compressed = stream.read(count)
                if len(compressed) != count:
                    raise ValueError("Truncated payload operation")
                if digest is not None and hashlib.sha256(compressed).digest() != digest:
                    raise ValueError(f"Compressed operation checksum mismatch: {part['name']}")
                decoded = lzma.decompress(compressed) if kind == OP_REPLACE_XZ else compressed
                extents = values(operation, 6)
                required = sum(first(extent, 2, 0) * block_size for extent in extents)
                if len(decoded) != required:
                    raise ValueError("Operation length doesn't match destination extents")
                pos = 0
                for extent in extents:
                    start, blocks = first(extent, 1, 0), first(extent, 2, 0)
                    dest, length = start * block_size, blocks * block_size
                    if dest < 0 or dest + length > size:
                        raise ValueError("Extent outside partition")
                    if any(k in touched for k in range(start, start + blocks)):
                        raise ValueError("Overlapping destination extents")
                    touched.update(range(start, start + blocks))
                    data[dest:dest + length] = decoded[pos:pos + length]
                    pos += length
            sha = hashlib.sha256(data).digest()
            if sha != expected:
                raise ValueError(f"Partition checksum mismatch: {part['name']}")
            stamps = sorted(set(s.decode("ascii") for s in
                                re.findall(rb"20\d{6}_\d{6}", data)))
            marker = data.find(b"check_part_overlapped done")
            print(f"VERIFIED {part['name']}: {size} bytes, SHA-256 {sha.hex()}")
            print(f"  build strings={stamps}; overlap marker offset={hex(marker) if marker >= 0 else 'not found'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ota", type=Path, help="Path to downloaded official OTA ZIP")
    parser.add_argument("--verify-bootloaders", action="store_true",
                        help="Read/decompress brhgptpl_* in memory and check signed-manifest hashes")
    args = parser.parse_args()
    with zipfile.ZipFile(args.ota) as z:
        partitions, blob_start, block_size, version = parse_manifest(z)
        print(f"Payload major version: {version}; block size: {block_size}")
        for part in partitions:
            digest = part["digest"]
            print(f"{part['name']}: size={part['size']} ops={len(part['operations'])}"
                  f" expected_sha256={digest.hex() if isinstance(digest, bytes) else '?'}")
        if args.verify_bootloaders:
            verify_brhgptpl(z, partitions, blob_start, block_size)
    print("Read-only analysis; no firmware image was written or flashed.")


if __name__ == "__main__":
    main()

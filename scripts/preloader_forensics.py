#!/usr/bin/env python3
"""Read-only structural inspection of a Crumpet NAND preloader excerpt."""
import argparse
import hashlib
import re
import struct
import urllib.request
from pathlib import Path

REFERENCE_URL = "https://raw.githubusercontent.com/jvandewiel/no-alexa/main/dumped_files/brhgptpl_0.bin"
REFERENCE_SHA256 = "e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637"
REPORTED_2023_SHA256 = "d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b"
MARKERS = (b"BOOTLOADER!", b"NFIINFO", b"FILE_INFO", b"crumpet",
           b"check_part_overlapped done", b"check_part_overlapped")
UPSTREAM_TARGETS = {
    "anti-rollback fuse": 0x00201954,
    "anti-rollback check": 0x002019B0,
    "TEE loader": 0x0020E19C,
    "DA verification": 0x00217F2C,
}

def inspect(label: str, data: bytes):
    sha = hashlib.sha256(data).hexdigest()
    print(f"\n=== {label} ===")
    print("Length:", len(data), "SHA-256:", sha)
    print("Public 2019 reference:", sha == REFERENCE_SHA256)
    print("Reported 2023 reference:", sha == REPORTED_2023_SHA256)
    stamps = sorted(set(m.decode() for m in re.findall(rb"20\d{6}_\d{6}", data)))
    print("Candidate timestamps:", stamps)
    for marker in MARKERS:
        pos = data.find(marker)
        print(f"{marker.decode()}: {hex(pos) if pos >= 0 else 'NOT FOUND'}")
    idx = data.find(b"MMM\x01")
    if idx >= 0 and data[idx+8:idx+17] == b"FILE_INFO" and idx+0x38 <= len(data):
        size = struct.unpack_from("<I", data, idx+4)[0]
        addr = struct.unpack_from("<I", data, idx+0x1c)[0]
        body = idx + size
        print(f"Candidate FILE_INFO at {idx:#x}, header length {size:#x}, load address {addr:#x}")
        if 0x20 <= size <= 0x1000 and 0x100000 <= addr <= 0x400000:
            print("CAUTION: candidate mapping only; multiple wrappers and runtime relocation are not resolved.")
            for label, target in UPSTREAM_TARGETS.items():
                file_offset = body + target - addr
                if 0 <= file_offset < len(data):
                    sample = data[file_offset:file_offset+24]
                    print(f"{label} ({target:#x}) => CANDIDATE offset {file_offset:#x}: {sample.hex(' ')}")
                else:
                    print(f"{label}: outside captured data in candidate mapping")
    print("Missing strings are NOT proof of a security fix. NEVER flash based on this tool.")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fetch-2019", action="store_true", help="Fetch public 2019 binary via HTTPS")
    p.add_argument("files", type=Path, nargs="*")
    args = p.parse_args()
    if not args.fetch_2019 and not args.files:
        p.error("provide file(s) or --fetch-2019")
    if args.fetch_2019:
        with urllib.request.urlopen(REFERENCE_URL, timeout=30) as f:
            data = f.read(2_000_000)
        inspect("public 2019 NAND excerpt", data)
    for path in args.files:
        inspect(str(path), path.read_bytes())

if __name__ == "__main__":
    main()

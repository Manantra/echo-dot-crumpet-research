#!/usr/bin/env python3
"""Read-only extraction of *metadata* about a MediaTek preloader's DRAM EMI block.

Matches the FILE_INFO/trailer method in MTKClient daconfig.m_extract_emi().
Never saves or prints the proprietary EMI block, and never accesses devices.
"""
import argparse
import hashlib
import re
import struct
from pathlib import Path

GFH = b"MMM\x01\x38\x00\x00\x00"
BLOADER = b"MTK_BLOADER_INFO_v"
MAX_EMI = 64 * 1024


def inspect(data):
    at = data.find(GFH)
    if at < 0:
        raise ValueError("MediaTek FILE_INFO header not found")
    payload = data[at:]
    if len(payload) < 0x38:
        raise ValueError("Truncated MediaTek FILE_INFO")
    image_size = struct.unpack_from("<I", payload, 0x20)[0]
    signature_size = struct.unpack_from("<I", payload, 0x2c)[0]
    if not 0x38 < signature_size < image_size <= len(payload):
        raise ValueError("FILE_INFO image/signature lengths inconsistent")
    body = payload[:image_size - signature_size]
    if len(body) < 0x804:
        raise ValueError("MediaTek body too small for advertised EMI trailer")
    length = struct.unpack_from("<I", body, len(body) - 4)[0]
    if length == 0:
        body = body[:-0x800]
        length = struct.unpack_from("<I", body, len(body) - 4)[0]
    if length <= len(BLOADER) + 2 or length > min(MAX_EMI, len(body) - 4):
        raise ValueError("Unreasonable preloader EMI block length")
    emi = body[-length - 4:-4]
    if not emi.startswith(BLOADER):
        raise ValueError("EMI trailer missing MTK_BLOADER_INFO_v marker")
    version = emi[len(BLOADER):len(BLOADER) + 2]
    if not re.fullmatch(rb"\d\d", version):
        raise ValueError("Invalid embedded BLOADER version")
    return {"version": version.decode("ascii"), "length": len(emi),
            "sha256": hashlib.sha256(emi).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path,
                   help="Previously obtained local Crumpet preloader image")
    args = p.parse_args()
    data = args.image.read_bytes()
    meta = inspect(data)
    print("Preloader image SHA-256:", hashlib.sha256(data).hexdigest())
    print(f"DRAM EMI metadata: MTK_BLOADER_INFO_v{meta['version']}")
    print(f"Length: {meta['length']} bytes")
    print("EMI SHA-256:", meta["sha256"])
    print("EMI bytes were not printed, written or transmitted.")


if __name__ == "__main__":
    main()

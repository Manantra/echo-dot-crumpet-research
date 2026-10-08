#!/usr/bin/env python3
"""Verify donor-era Crumpet Amonet function pointers that map into ASCII data.

Read only the public 2019 Crumpet brhgptpl_0.bin with EXACT pinned SHA-256
and the unmodified upstream include/devices/crumpet.h header. No firmware
is written, no ARM payload is made or run, no device or USB interaction.
"""
import argparse
import hashlib
from pathlib import Path
import re

from disassemble_preloader import address_to_offset, locate_image

PUBLIC_2019_IMAGE_SHA256 = (
    "e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637"
)
CANDIDATE_SYMBOLS = ("TEE_SET_ENTRY_ADDR", "MTEE_VERIFY_DECRYPT_ADDR")
CONFIRMED_CONTEXT = {
    "TEE_SET_ENTRY_ADDR": b"[CA Training] Frequency=%d, Rank=%d",
    "MTEE_VERIFY_DECRYPT_ADDR":
        b"the MTEE image required external memory size",
}


def macro_addr(header, name):
    matches = re.findall(
        r"(?m)^\s*#define\s+" + re.escape(name) +
        r"\s+(0x[0-9a-fA-F]+)\s*$", header)
    if len(matches) != 1:
        raise ValueError(f"Expected one literal {name}")
    return int(matches[0], 16)


def printable_nul_string_covering(data, site, max_length=256):
    """Return a NUL-bounded printable ASCII string spanning site or None."""
    if site < 0 or site >= len(data):
        raise ValueError("Pointer mapped outside image")
    left = data.rfind(b"\x00", max(0, site - max_length), site + 1)
    right = data.find(b"\x00", site, min(len(data), site + max_length + 1))
    if left < 0 or right < 0:
        return None
    start = left + 1
    if not start <= site < right or right - start < 22:
        return None
    chunk = data[start:right]
    if not all(32 <= c <= 126 or c in (9, 10, 13) for c in chunk):
        return None
    if b" " not in chunk or sum(65 <= c <= 90 or 97 <= c <= 122
                                for c in chunk) < 14:
        return None
    return {"start": start, "end": right,
            "site_index": site - start,
            "ascii": chunk.decode("ascii")}


def analyze_2019(header, data):
    sha = hashlib.sha256(data).hexdigest()
    if sha != PUBLIC_2019_IMAGE_SHA256:
        raise ValueError("Only the pinned public 2019 Crumpet image is accepted")
    _, load = locate_image(data)
    if load != 0x200D00:
        raise ValueError("Unexpected stored Preloader encoded RAM base")
    results = {}
    for name in CANDIDATE_SYMBOLS:
        addr = macro_addr(header, name)
        off = address_to_offset(data, addr, 4)
        span = printable_nul_string_covering(data, off)
        if span is None:
            raise ValueError(f"{name} does not map inside a NUL-terminated string")
        if CONFIRMED_CONTEXT[name] not in span["ascii"].encode("ascii"):
            raise ValueError(f"{name} text identity changed")
        results[name] = {"vma": addr, "file_offset": off, **span}
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original_crumpet_h", type=Path,
                   help="Local public amonet/include/devices/crumpet.h")
    p.add_argument("public_2019_boot_image", type=Path,
                   help="Local public no-alexa/dumped_files/brhgptpl_0.bin")
    args = p.parse_args()
    header = args.original_crumpet_h.read_text(encoding="utf-8")
    image = args.public_2019_boot_image.read_bytes()
    print("Public 2019 Crumpet stored-image pointer/data collision audit")
    for name, result in analyze_2019(header, image).items():
        print(name, f"VMA={result['vma']:#x}",
              f"mapped_file_offset={result['file_offset']:#x}")
        print("  Containing ASCII:", repr(result["ascii"]))
        print("  Character index in string:", result["site_index"])
    print("Both original C function pointers address confirmed string payloads "
          "within this specific archived stored image.")
    print("This is not a live RAM snapshot or proof about a different 2019 donor.")
    print("No binaries changed, no exploit generated, no device contacted.")


if __name__ == "__main__":
    main()

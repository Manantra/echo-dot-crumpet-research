#!/usr/bin/env python3
"""Read-only SRAM overlap audit of a 2023-era Crumpet preloader.

Extracts initialized text/BSS range values by following four literal-relative
pointers in the verified 2023-built range guard. This is NOT a security test
or a bootloader exploitation tool: it does not execute, modify or flash data.
"""
import argparse
import struct
from pathlib import Path

from disassemble_preloader import address_to_offset, locate_image

# Offsets are specific to the newer Crumpet builds (2023-07 and 2023-11).
# A source-code/bytewise-disassembly cross-check is essential for other builds.
PC_RELATIVE_BOUNDS = {
    "text_start": (0x20F200, 0x20F1A4),
    "text_end":   (0x20F204, 0x20F1A8),
    "bss_start":  (0x20F214, 0x20F1D8),
    "bss_end":    (0x20F218, 0x20F1DC),
}
DEFAULT_BDEV_ADDR = 0x001086EC  # From upstream Crumpet device config.


def read_u32(data, address, signed=False):
    fmt = "<i" if signed else "<I"
    file_off = address_to_offset(data, address, 4)
    return struct.unpack_from(fmt, data, file_off)[0]


def extract_protected_ranges(data):
    # This simple evidence marker helps avoid applying the newer map to older
    # images. It is NOT cryptographic proof of image version.
    if (b"load range overlap text region" not in data or
            b"load range overlap bss region" not in data):
        raise ValueError("Not the expected newer guarded Crumpet image")
    bounds = {}
    for label, (literal_addr, add_instruction_addr) in PC_RELATIVE_BOUNDS.items():
        relative = read_u32(data, literal_addr, signed=True)
        pointer = (add_instruction_addr + 4 + relative) & 0xFFFFFFFF
        bounds[label] = read_u32(data, pointer)
    text = (bounds["text_start"], bounds["text_end"])
    bss = (bounds["bss_start"], bounds["bss_end"])
    for start, end in (text, bss):
        if not 0 <= start < end <= 0x100000000:
            raise ValueError("Invalid calculated memory interval")
    return {"text": text, "bss": bss}


def crafted_subimage_size(block_device):
    """Recreate the published generator's length formula, no payload."""
    read_callback = block_device + 0x20
    return ((read_callback + 4 + 0x1FF) & ~0x1FF) + 4


def overlap_with(range_a, range_b):
    """Compare non-wrapping, half-open intervals."""
    a0, a1 = range_a
    b0, b1 = range_b
    if not (0 <= a0 <= a1 <= 0x100000000 and
            0 <= b0 <= b1 <= 0x100000000):
        raise ValueError("Invalid interval")
    return a0 < b1 and b0 < a1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Locally obtained preloader (not written or modified)")
    parser.add_argument("--bdev-addr", type=lambda x: int(x, 0),
                        default=DEFAULT_BDEV_ADDR)
    parser.add_argument("--candidate-start", type=lambda x: int(x, 0), default=0,
                        help="Hypothetical effective destination address, default 0")
    args = parser.parse_args()
    data = args.image.read_bytes()
    entry, load = locate_image(data)
    print(f"Validated stored-image entry {entry:#x} and encoded load address {load:#x}")
    regions = extract_protected_ranges(data)
    for label, (start, end) in regions.items():
        print(f"{label}: [{start:#010x}, {end:#010x}), size={end-start:#x}")
    target = args.bdev_addr
    size = crafted_subimage_size(target)
    copy = (args.candidate_start, args.candidate_start + size)
    if copy[1] > 0x100000000:
        raise ValueError("Candidate copy wraps the 32-bit address space")
    print(f"Upstream block-device target: {target:#010x}")
    print(f"Upstream crafted data size: {size:#x}")
    print(f"Hypothetical copy: [{copy[0]:#010x}, {copy[1]:#010x})")
    for label, region in regions.items():
        inside = region[0] <= target < region[1]
        intersects = overlap_with(copy, region)
        print(f"{label}: block-device target inside={inside}; copy intersects={intersects}")
    print("CONDITIONAL result only. Real runtime header translation and control flow are not modeled.")


if __name__ == "__main__":
    main()

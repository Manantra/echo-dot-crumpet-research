#!/usr/bin/env python3
"""Audit a pinned amonet Crumpet PART_GET function-pointer address, read-only.

For a source-proven *linear Thumb instruction sequence* around the fixed
PART_GET_ADDR, detect whether the target lies at an instruction boundary or
inside a 32-bit Thumb-2 instruction.

Input: an already-obtained local, manifest-verified Crumpet Preloader image
and the original local amonet Crumpet device header. Never alters a firmware
image, executes an ARM payload or communicates with hardware.

A valid instruction boundary is NOT sufficient to prove a callable function.
A static file-to-VMA map is NOT a measurement of actual live RAM relocation.
"""
import argparse
import hashlib
from pathlib import Path
import re

from disassemble_preloader import address_to_offset, locate_image

# Both anchor locations were validated against repeated disassembly windows,
# including branch/BL instruction boundaries, on *these specific image hashes*.
# New firmware hashes require separately proving the anchor; fail closed.
KNOWN = {
    "e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637":
        ("public-2019-archive", 0x20F248, bytes.fromhex("9c4200f0")),
    "a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5":
        ("official-2021", 0x20F248, bytes.fromhex("06f012fb")),
    "990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d":
        ("official-2022", 0x20F248, bytes.fromhex("e3e0daf8")),
    "837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a":
        ("official-2025-nov", 0x20F24A, bytes.fromhex("20682946")),
}


def parse_part_get_address(header):
    match = re.findall(r"(?m)^#define\s+PART_GET_ADDR\s+(0x[0-9A-Fa-f]+)\s*$",
                       header)
    if len(match) != 1:
        raise ValueError("Expected exactly one PART_GET_ADDR in the device header")
    return int(match[0], 16)


def thumb_boundary(image, address, anchor, prefix, max_instructions=32):
    """Return the target's surrounding instructions from a validated anchor."""
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError as exc:
        raise RuntimeError("Capstone 4/5 is required for Thumb boundary checks") from exc
    if not (anchor <= address < anchor + 0x70):
        raise ValueError("Target outside bounded Thumb basic-block excerpt")
    _, base = locate_image(image)
    if base != 0x200D00:
        raise ValueError("Unexpected encoded firmware load base")
    offset = address_to_offset(image, anchor, 0x70)
    if image[offset:offset + len(prefix)] != prefix:
        raise ValueError("Anchor fingerprint mismatch: unsupported code path")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoded = list(cs.disasm(image[offset:offset + 0x70], anchor,
                             count=max_instructions))
    if not decoded or decoded[0].address != anchor:
        raise ValueError("Invalid/undecodable Thumb anchor")
    covering = next(
        (ins for ins in decoded if ins.address <= address < ins.address + ins.size),
        None)
    if covering is None:
        raise ValueError("Target not reached by disassembly from supplied anchor")
    preceding = [ins for ins in decoded if ins.address < covering.address]
    return {
        "target": address,
        "anchor": anchor,
        "relation": ("middle_of_thumb2_instruction"
                     if covering.address < address else
                     "instruction_boundary_not_function_proof"),
        "containing_vma": covering.address,
        "containing_size": covering.size,
        "containing_mnemonic": covering.mnemonic,
        "containing_operands": covering.op_str,
        "preceding_vma": preceding[-1].address if preceding else None,
        "preceding_mnemonic": preceding[-1].mnemonic if preceding else None,
        "raw_at_containing": image[
            address_to_offset(image, covering.address, covering.size):
            address_to_offset(image, covering.address, covering.size)
            + covering.size].hex(),
    }


def inspect_verified_image(header, data):
    sha = hashlib.sha256(data).hexdigest()
    if sha not in KNOWN:
        raise ValueError("Unknown full partition SHA-256; anchor not validated")
    build, anchor, prefix = KNOWN[sha]
    address = parse_part_get_address(header)
    return {"build": build, "partition_sha256": sha,
            **thumb_boundary(data, address, anchor, prefix)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("upstream_crumpet_header", type=Path,
                    help="Original local amonet include/devices/crumpet.h")
    ap.add_argument("preloader_images", type=Path, nargs="+",
                    help="Local verified, unchanged archived or official Crumpet boot partitions")
    args = ap.parse_args()
    header = args.upstream_crumpet_header.read_text(encoding="utf-8")
    for file in args.preloader_images:
        result = inspect_verified_image(header, file.read_bytes())
        print("IMAGE:", file.name, "verified build:", result["build"])
        print("PART_GET_ADDR:", hex(result["target"]),
              "status:", result["relation"])
        print("Thumb instruction:", hex(result["containing_vma"]),
              f"+{result['containing_size']}", result["containing_mnemonic"],
              result["containing_operands"],
              "raw", result["raw_at_containing"])
        print("Preceding instruction:", result["preceding_vma"],
              result["preceding_mnemonic"])
    print("A pointer into the second half of a Thumb-2 instruction is not a "
          "normal callable Thumb function entry in this stored image.")
    print("No conclusions about separate live RAM relocation; no device writes.")


if __name__ == "__main__":
    main()

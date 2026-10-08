#!/usr/bin/env python3
"""Read-only A32 startup literal and Thumb-handoff audit for Crumpet preloaders.

This decodes the GFH-anchored *stored-file* image (not live device RAM) and
checks the explicit ARM instructions controlling BSS zero-fill and the
indirect ARM->Thumb handoff. It makes no firmware alterations or USB calls.

Known tested builds: archived 2019 and official 2021/2022/2025 Crumpet.
The exact opcode checks intentionally fail on different startup routines.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from disassemble_preloader import locate_image, address_to_offset

# Instructions at offsets relative to the encoded ARM entry 0x00200D00:
# 0xB0/0xB4 are literal loads from +8/+0xC; 0xC4–0xD0 is the zeroing loop.
# 0xF4 loads the continuation argument; 0xF8 branches to the indirect
# PC-load at +0x14C, which obtains an odd Thumb continuation pointer.
REQUIRED_OPCODES = {
    0x004: 0xEA000003,  # B +0x18
    0x0B0: 0xE51F00B0,  # LDR R0,[PC,#-0xB0] -> +0x08
    0x0B4: 0xE51F10B0,  # LDR R1,[PC,#-0xB0] -> +0x0C
    0x0BC: 0xE1500001,  # CMP R0,R1
    0x0C0: 0x0A000003,  # BEQ +0xD4
    0x0C4: 0xE5802000,  # STR R2,[R0]
    0x0C8: 0xE2800004,  # ADD R0,R0,#4
    0x0CC: 0xE1500001,  # CMP R0,R1
    0x0D0: 0x1AFFFFFB,  # BNE +0xC4
    0x0D4: 0xE51F00CC,  # LDR R0,[PC,#-0xCC] -> +0x10
    0x0D8: 0xE51F10CC,  # LDR R1,[PC,#-0xCC] -> +0x14
    0x0DC: 0xE59F2064,  # LDR R2,[PC,#0x64] -> +0x148
    0x0E0: 0xE5802000,  # STR R2,[R0]
    0x0F4: 0xE59F0048,  # LDR R0,[PC,#0x48] -> +0x144
    0x0F8: 0xEA000013,  # B +0x14C
    0x14C: 0xE51FF004,  # LDR PC,[PC,#-4] -> +0x150
}


def decode_startup(data):
    entry, load = locate_image(data)
    if load != 0x00200D00:
        raise ValueError("Unexpected encoded SRAM entry/base")
    for rel, expected in REQUIRED_OPCODES.items():
        actual = struct.unpack_from("<I", data, entry + rel)[0]
        if actual != expected:
            raise ValueError(
                f"Startup opcode mismatch at +{rel:#x}: "
                f"expected {expected:#010x}, got {actual:#010x}")

    bss_start, bss_end = struct.unpack_from("<II", data, entry + 8)
    if (not (0x00100000 <= bss_start < bss_end <= 0x00200000)
            or (bss_start | bss_end) & 3):
        raise ValueError("Invalid/alignment-disputed SRAM BSS limits")
    control_addr, runtime_source_addr = struct.unpack_from("<II", data, entry + 0x10)
    fixed_arg = struct.unpack_from("<I", data, entry + 0x144)[0]
    debug_marker = struct.unpack_from("<I", data, entry + 0x148)[0]
    thumb_pointer = struct.unpack_from("<I", data, entry + 0x150)[0]
    if not thumb_pointer & 1:
        raise ValueError("ARM-to-Thumb continuation pointer is not odd")
    thumb_vma = thumb_pointer & ~1
    continuation_offset = address_to_offset(data, thumb_vma, 4)
    if continuation_offset < entry or thumb_vma < load:
        raise ValueError("Thumb continuation outside image")
    return {
        "entry_offset": entry,
        "encoded_base": load,
        "bss_start": bss_start,
        "bss_end_exclusive": bss_end,
        "bss_bytes": bss_end - bss_start,
        "control_address": control_addr,
        "runtime_source_address": runtime_source_addr,
        "handoff_argument": fixed_arg,
        "debug_marker": debug_marker,
        "thumb_pointer": thumb_pointer,
        "thumb_stored_offset": continuation_offset,
        "image_sha256": hashlib.sha256(data).hexdigest(),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("images", type=Path, nargs="+")
    args = ap.parse_args()
    for path in args.images:
        a = decode_startup(path.read_bytes())
        print(path.name, "SHA256", a["image_sha256"])
        print("  encoded ARM load", hex(a["encoded_base"]),
              "entry file offset", hex(a["entry_offset"]))
        print("  verified ARM BSS-clear loop:",
              f"[{a['bss_start']:#010x},{a['bss_end_exclusive']:#010x})",
              a["bss_bytes"], "bytes")
        print("  ARM startup writes marker",
              hex(a["debug_marker"]), "to SRAM control", hex(a["control_address"]))
        print("  follow-on runtime-source pointer:", hex(a["runtime_source_address"]),
              "(contents can be runtime-initialized; do not interpret file bytes "
              "as reliable current RAM)")
        print("  handoff argument", hex(a["handoff_argument"]),
              "indirect Thumb target", hex(a["thumb_pointer"]),
              "stored file offset", hex(a["thumb_stored_offset"]))
    print("These are encoded/stored-image properties; live relocation is unproven.")
    print("No patches, USB traffic, flash operations or hardware tests performed.")


if __name__ == "__main__":
    main()

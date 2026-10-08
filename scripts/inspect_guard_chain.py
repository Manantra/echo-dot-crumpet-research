#!/usr/bin/env python3
"""Read-only call-chain check for 2023-era Crumpet Preloader OTA images.

Requires Capstone (pip install 'capstone>=4,<6').
The address constants below were recovered from an SHA-256-verified official
Crumpet OTA preloader with embedded build 20230726_065225.
This is NOT an exploit, firmware patcher, device tool, or vulnerability oracle.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from disassemble_preloader import locate_image, address_to_offset

# Version-specific locations; do not apply to 2019/2021/2022 images.
REGION_REFERENCES = (
    ("text_start", 0x20F1A4, 0x20F200),
    ("text_end", 0x20F1A8, 0x20F204),
    ("bss_start", 0x20F1D8, 0x20F214),
    ("bss_end", 0x20F1DC, 0x20F218),
)
CALL_CHAIN = (
    ("initial 0x200-byte header read", 0x20F3F8, 0x20210C),
    ("primary address-range guard", 0x20F490, 0x20F1A0),
    ("larger payload read", 0x20F50E, 0x20210C),
    ("alternate address-range guard", 0x20F68E, 0x20F1A0),
    ("alternate payload read", 0x20F6FE, 0x20210C),
    ("ATF subimage loader", 0x20DF74, 0x20F3AC),
    ("ATF verify/decode candidate", 0x20DF90, 0x216100),
    ("TEE subimage loader", 0x20DFC6, 0x20F3AC),
    ("TEE verify/decode candidate", 0x20DFEC, 0x216100),
)
# Upstream amonet-koboreru include/devices/crumpet.h, not derived from image.
UPSTREAM_BDEV_ADDR = 0x001086EC


def u32(data, vma):
    offset = address_to_offset(data, vma, 4)
    return struct.unpack_from("<I", data, offset)[0]


def instruction(data, vma):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError as exc:
        raise RuntimeError("Please install capstone>=4,<6") from exc
    offset = address_to_offset(data, vma, 4)
    candidate = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(
        data[offset:offset + 4], vma, count=1))
    if not candidate:
        raise ValueError(f"Cannot decode Thumb instruction at {vma:#x}")
    return candidate[0]


def inspect(data):
    entry, load = locate_image(data)
    if (entry, load) != (0x8300, 0x00200D00):
        raise ValueError("Unexpected image format; this tool targets 2023-era OTA images")
    bounds = {}
    for name, add_addr, literal_addr in REGION_REFERENCES:
        ins = instruction(data, add_addr)
        if not ins.mnemonic.startswith("add") or "pc" not in ins.op_str:
            raise ValueError(f"Unexpected instruction at {add_addr:#x}: {ins.mnemonic}")
        relative = u32(data, literal_addr)
        pointer = add_addr + 4 + relative
        bounds[name] = u32(data, pointer)
    for section in ("text", "bss"):
        a, z = bounds[f"{section}_start"], bounds[f"{section}_end"]
        if not 0 < a < z < 0x10000000:
            raise ValueError(f"Unreasonable {section} bounds")
    observed = []
    for label, addr, target in CALL_CHAIN:
        ins = instruction(data, addr)
        if ins.mnemonic != "bl" or ins.op_str.strip() != f"#{target:#x}":
            raise ValueError(f"Call-chain mismatch at {addr:#x}: "
                             f"{ins.mnemonic} {ins.op_str}, expected {target:#x}")
        observed.append((label, addr, target))
    # In this specific decoded function, a failed guard reaches an error-report
    # path instead of branching directly to the transfer.
    cond = instruction(data, 0x20F494)
    if cond.mnemonic != "cbnz" or "#0x20f4a6" not in cond.op_str:
        raise ValueError("Primary guard return-value branch differs")
    return bounds, observed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path, help="Local, independently obtained Crumpet OTA preloader image")
    args = p.parse_args()
    binary = args.image.read_bytes()
    bounds, calls = inspect(binary)
    print("Local image SHA-256:", hashlib.sha256(binary).hexdigest())
    for label in ("text", "bss"):
        print(f"VALIDATED {label}: {bounds[label+'_start']:#010x} "
              f"to {bounds[label+'_end']:#010x} (exclusive)")
    inside = bounds["bss_start"] <= UPSTREAM_BDEV_ADDR < bounds["bss_end"]
    print(f"Upstream BDEV_ADDR {UPSTREAM_BDEV_ADDR:#010x} inside protected BSS:", inside)
    for label, caller, dest in calls:
        print(f"VERIFIED {label}: {caller:#010x} BL {dest:#010x}")
    print("WARNING: static evidence only; no device execution or exploit outcome established.")


if __name__ == "__main__":
    main()

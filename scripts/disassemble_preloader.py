#!/usr/bin/env python3
"""Read-only ARM/Thumb disassembly of MediaTek Crumpet bootloader images.

Requires: pip install capstone
Does not flash, patch, or write firmware. The input binary is opened read-only.

The VMA mapping is validated using the MediaTek FILE_INFO load address and a
recognizable ARM branch at the executable entry. That check is necessary but
is NOT proof the ROM copies every region without relocation at runtime.
"""
import argparse
import hashlib
import re
import struct
from pathlib import Path

ENTRY_OFFSET_FROM_FILE_INFO = 0x300
ARM_ENTRY_BRANCH = b"\x03\x00\x00\xea"


def locate_image(data):
    """Return (file_offset_of_code_entry, encoded_load_address)."""
    for marker in re.finditer(b"FILE_INFO\x00", data):
        head = marker.start() - 8
        if head < 0 or data[head:head + 4] != b"MMM\x01":
            continue
        if struct.unpack_from("<I", data, head + 4)[0] != 0x38:
            continue
        entry = head + ENTRY_OFFSET_FROM_FILE_INFO
        if entry + 8 > len(data):
            continue
        if data[entry + 4:entry + 8] != ARM_ENTRY_BRANCH:
            continue
        load = struct.unpack_from("<I", data, head + 0x1c)[0]
        return entry, load
    raise ValueError("No validated MediaTek FILE_INFO + ARM entry marker found")


def address_to_offset(data, runtime_address, length=1):
    entry, load = locate_image(data)
    if runtime_address < load:
        raise ValueError("Address below the encoded load address")
    off = entry + runtime_address - load
    if off < 0 or off + length > len(data):
        raise ValueError("Address range not present in the input file")
    return off


def disassemble(data, runtime_address, length, thumb=True):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
    except ImportError as exc:
        raise SystemExit(
            "Capstone is required for disassembly. Install with: pip install capstone"
        ) from exc

    off = address_to_offset(data, runtime_address, length)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    return [(ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str)
            for ins in cs.disasm(data[off:off + length], runtime_address)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--address", type=lambda s: int(s, 0), required=True,
                   help="Virtual address, e.g. 0x20f1a0")
    p.add_argument("--length", type=lambda s: int(s, 0), default=0x70,
                   help="Byte count to disassemble (default 0x70)")
    p.add_argument("--arm", action="store_true",
                   help="Disassemble in ARM mode rather than Thumb mode")
    args = p.parse_args()

    data = args.image.read_bytes()
    entry, load = locate_image(data)
    print("File:", args.image)
    print("Bytes:", len(data), "SHA-256:", hashlib.sha256(data).hexdigest())
    print("Encoded load address:", hex(load), "executable offset:", hex(entry))
    print("WARNING: only the file mapping is checked; runtime relocation unproven.")
    print("Requested virtual address:", hex(args.address),
          "file offset:", hex(address_to_offset(data, args.address, args.length)))
    print("Mode:", "ARM" if args.arm else "Thumb")
    for vma, hexbytes, mnemonic, operands in disassemble(
            data, args.address, args.length, thumb=not args.arm):
        print(f"  0x{vma:08x}  {hexbytes:<12} {mnemonic:<10} {operands}")


if __name__ == "__main__":
    main()

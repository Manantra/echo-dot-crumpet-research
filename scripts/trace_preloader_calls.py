#!/usr/bin/env python3
"""Read-only direct Thumb call-site scanner for a Crumpet preloader image.

Requires Capstone and the companion disassemble_preloader module.
Scanning an arbitrary byte interval can decode embedded constants or data as
false instructions; confirm every candidate by inspecting surrounding code.
Never uses, patches, or communicates with hardware.
"""
import argparse
from pathlib import Path

from disassemble_preloader import address_to_offset, locate_image


def direct_calls(data, begin, length):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    file_offset = address_to_offset(data, begin, length)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    found = []
    for ins in cs.disasm(data[file_offset:file_offset + length], begin):
        if ins.mnemonic not in ("bl", "blx"):
            continue
        if not ins.op_str.startswith("#"):
            continue  # dynamic branch target, not statically resolved
        try:
            dest = int(ins.op_str[1:], 0)
        except ValueError:
            continue
        found.append((ins.address, dest, ins.mnemonic))
    return found


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--begin", type=lambda s: int(s, 0), required=True,
                   help="Virtual start address, e.g. 0x20df40")
    p.add_argument("--length", type=lambda s: int(s, 0), required=True)
    p.add_argument("--target", type=lambda s: int(s, 0), action="append",
                   help="Repeat to filter for particular destination addresses")
    args = p.parse_args()
    data = args.image.read_bytes()
    entry, load = locate_image(data)
    print(f"Image entry: file {entry:#x}, encoded load address {load:#x}")
    print("WARNING: file-memory mapping is not proof of runtime relocation.")
    for site, dest, mnemonic in direct_calls(data, args.begin, args.length):
        if args.target and dest not in args.target:
            continue
        print(f"0x{site:08x}: {mnemonic} 0x{dest:08x}")


if __name__ == "__main__":
    main()

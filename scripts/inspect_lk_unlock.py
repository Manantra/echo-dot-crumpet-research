#!/usr/bin/env python3
"""Read-only audit of Amazon Crumpet LK vendor Fastboot unlock dispatch.

Targets one independently manifest-SHA-256-verified OTA LK image only:
May-2025 official Crumpet OTA, LK build 20230407_002912.
No device I/O, no flashing, no secret extraction, no certificate generation.

Install optional disassembly dependency: pip install 'capstone>=4,<6'
"""
import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d"
EXPECTED_BYTES = 237568

# Addresses below are FILE OFFSETS in the exact 2025-OTA LK image, not VMAs.
STRINGS = {
    "generic flash prefix": (0x34BEA, b"flash:"),
    "unlock subcommand": (0x2DF8A, b"unlock"),
    "one-time certificate subcommand": (0x2DF97, b"otucert"),
    "one-time code subcommand": (0x2DFA5, b"otucode"),
    "signed unlock verification name": (0x25230, b"amzn_verify_unlock"),
    "one-time certificate validation error": (0x25445, b"Verify one time unlock cert fail"),
    "locked command diagnostic": (0x34AC8, b"the command you input is restricted on locked hw"),
}

# Thumb branch targets are FILE OFFSETS. Tests check decoded instructions,
# not just an untrusted text-string presence.
CALLS = {
    "register generic flash prefix": (0x1E666, 0x1E110),
    "unlock string comparison": (0x1F7FA, 0x20C36),
    "unlock validation": (0x1F804, 0x1C48),
    "unlock certificate verification backend": (0x1CA6, 0x1B10),
    "certificate-writing request handler": (0x1F85E, 0x1DC8),
    "code-writing request handler": (0x1F87C, 0x1E18),
}

# Which Thumb literal loads feed an ADD reg,PC instruction. This confirms
# which actual strings the command dispatch compares against.
LITERAL_REFERENCES = {
    "generic prefix": (0x1E658, 0x1E662, 0x34BEA),
    "unlock suffix": (0x1F7F4, 0x1F7F8, 0x2DF8A),
    "otucert suffix": (0x1F84E, 0x1F852, 0x2DF97),
    "otucode suffix": (0x1F86C, 0x1F870, 0x2DFA5),
}


def one_thumb_instruction(data, address):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError as exc:
        raise RuntimeError("Install capstone>=4,<6 for LK disassembly") from exc
    if not 0 <= address < len(data):
        raise ValueError("Instruction address outside image")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    result = list(cs.disasm(data[address:address + 4], address, count=1))
    if not result:
        raise ValueError(f"Cannot decode instruction at {address:#x}")
    return result[0]


def pc_relative_destination(data, ldr_address, add_address):
    """Decode a known LDR Rt,[PC,#imm] + ADD Rt,PC string-reference pair."""
    ldr = one_thumb_instruction(data, ldr_address)
    add = one_thumb_instruction(data, add_address)
    if not ldr.mnemonic.startswith("ldr") or "[pc," not in ldr.op_str:
        raise ValueError(f"Expected PC literal load at {ldr_address:#x}")
    if not add.mnemonic.startswith("add") or "pc" not in add.op_str:
        raise ValueError(f"Expected ADD with PC at {add_address:#x}")
    # Known Thumb-1 16-bit LDR literal encoding T1, Rt in bits [10:8],
    # imm8*4 from Align(PC+4,4).
    opcode = struct.unpack_from("<H", data, ldr_address)[0]
    if opcode & 0xF800 != 0x4800:
        raise ValueError("Unexpected non-T1 LDR literal encoding")
    register = (opcode >> 8) & 7
    if not ldr.op_str.startswith(f"r{register},") or not add.op_str.startswith(f"r{register},"):
        raise ValueError("LDR/ADD destination register mismatch")
    literal_address = ((ldr_address + 4) & ~3) + (opcode & 0xFF) * 4
    if literal_address + 4 > len(data):
        raise ValueError("Literal word outside image")
    delta = struct.unpack_from("<i", data, literal_address)[0]
    return (add_address + 4 + delta) & 0xFFFFFFFF


def inspect(data, strict=True):
    sha = hashlib.sha256(data).hexdigest()
    if strict and (len(data) != EXPECTED_BYTES or sha != EXPECTED_SHA256):
        raise ValueError("LK image is not the expected verified official Crumpet OTA build")
    for label, (offset, marker) in STRINGS.items():
        if data[offset:offset + len(marker)] != marker:
            raise ValueError(f"Missing verified string marker: {label} at {offset:#x}")
    found = {}
    for label, (site, expected_target) in CALLS.items():
        ins = one_thumb_instruction(data, site)
        if ins.mnemonic != "bl" or ins.op_str != f"#{expected_target:#x}":
            raise ValueError(f"Unexpected call at {site:#x}: {ins.mnemonic} {ins.op_str}")
        found[label] = (site, expected_target)
    for label, (ldr, add, expected_offset) in LITERAL_REFERENCES.items():
        actual = pc_relative_destination(data, ldr, add)
        if actual != expected_offset:
            raise ValueError(f"{label} string reference mismatch: {actual:#x}")
    # Verify that the command-handler outcome gates further operations.
    check = one_thumb_instruction(data, 0x1F808)
    if check.mnemonic != "cbz" or check.op_str != "r0, #0x1f818":
        raise ValueError("Unlock validation status branch differs")
    return sha, found


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path,
                   help="Previously obtained local LK image (read only)")
    a = p.parse_args()
    data = a.image.read_bytes()
    sha, matches = inspect(data)
    print(f"VERIFIED LK SHA-256: {sha}")
    print("Encoded LK build: 20230407_002912")
    for label, (site, target) in matches.items():
        print(f"  {label}: FILE+{site:#x}  BL FILE+{target:#x}")
    for label, (ldr, add, offset) in LITERAL_REFERENCES.items():
        print(f"  verified literal: {label} via {ldr:#x}->{add:#x} to FILE+{offset:#x}")
    print("Result: registered generic flash dispatch; unlock branch requires a")
    print("validation-success result. This does NOT provide a signing certificate.")
    print("No device accessed, no firmware modified, no unlock performed.")


if __name__ == "__main__":
    main()

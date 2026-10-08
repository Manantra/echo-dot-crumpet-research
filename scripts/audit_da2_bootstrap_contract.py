#!/usr/bin/env python3
"""Offline validation of MT8167 DA1 -> DA2 runtime-argument/USB-SYNC contract.

Runs only on original, hash-pinned MTKClient loader files from cd25cf9.
Uses Capstone 4/5 disassembly but NEVER executes code, contacts USB, uploads
an agent, reads device state or alters flash. No vendor binary distributed.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory

ROM_BASE = 0x40000000
MAGIC_ARGUMENT = 0xFE4A4D42
MAGIC_PROTOCOL = 0xFEEEEEEF
SYNC = 0x434E5953

# Independently verified full original DA container hash, VA sites and sizes.
KNOWN = {
    "MTK_DA_V5.bin": {
        "sha": "aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f",
        "da1_magic": 0x1594,
        "entry": 0x40000C3C, "copy_size": 0x58,
        "copy_dst": 0x400638D0, "copy_fn": 0x4000AC10,
        "thread_ptr_ldr": 0x40000CE2,
        "bootstrap": 0x40001D74, "magic_ptr_ldr": 0x40001D86,
        "magic_val_ldr": 0x40001D88, "magic_check": 0x40001D8C,
        "halt": 0x40001D9E, "error_ldr": 0x40001D98,
        "ready_call": 0x40001E92, "ready": 0x40006E88,
        "command_call": 0x40001E96, "command": 0x40006C68,
        "frame_sender": 0x40006DEC, "frame_literal": 0x40006E30,
        "io_table": 0x40053540, "send_wrapper": 0x4000A9B8,
    },
    "MTK_AllInOne_DA_mt6590.bin": {
        "sha": "49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64",
        "da1_magic": 0x1078,
        "entry": 0x40000A48, "copy_size": 0x40,
        "copy_dst": 0x4003F430, "copy_fn": 0x40007718,
        "thread_ptr_ldr": 0x40000AF8,
        "bootstrap": 0x40001428, "magic_ptr_ldr": 0x40001438,
        "magic_val_ldr": 0x4000143A, "magic_check": 0x4000143E,
        "halt": 0x40001450, "error_ldr": 0x4000144A,
        "ready_call": 0x400014F0, "ready": 0x40004BE0,
        "command_call": 0x400014F4, "command": 0x40004A34,
        "frame_sender": 0x40004B58, "io_table": 0x40030850,
        "send_wrapper": 0x40004B58,
    },
}


def word(code, address, base=ROM_BASE):
    pos = address - base
    if pos < 0 or pos + 4 > len(code):
        raise ValueError("Requested word outside firmware body")
    return struct.unpack_from("<I", code, pos)[0]


def instruction(code, address, thumb=True, base=ROM_BASE):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    except ImportError as exc:
        raise RuntimeError("Capstone 4/5 required for verified instruction audit") from exc
    if address < base or address + 4 > base + len(code):
        raise ValueError("Code address outside body")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    cs.detail = True
    decoded = list(cs.disasm(code[address-base:address-base+8], address, count=1))
    if len(decoded) != 1 or decoded[0].address != address:
        raise ValueError("Expected one decoded instruction")
    return decoded[0]


def expect(code, addr, mnemonic, op_substring=None, thumb=True):
    i = instruction(code, addr, thumb=thumb)
    if i.mnemonic != mnemonic or (
            op_substring is not None and op_substring not in i.op_str):
        raise ValueError(
            f"Unexpected instruction at {addr:#x}: {i.mnemonic} {i.op_str}; "
            f"wanted {mnemonic} {op_substring}")
    return i


def pc_literal(code, addr):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    ins = instruction(code, addr)
    if (not ins.mnemonic.startswith("ldr")
            or len(ins.operands) < 2
            or ins.operands[1].type != ARM_OP_MEM
            or ins.operands[1].mem.base != ARM_REG_PC):
        raise ValueError(f"Not a Thumb PC-relative literal load at {addr:#x}")
    lit_va = ((addr + 4) & ~3) + ins.operands[1].mem.disp
    return word(code, lit_va)


def branch_target(code, addr, mnemonic="bl"):
    from capstone.arm import ARM_OP_IMM
    ins = expect(code, addr, mnemonic)
    if len(ins.operands) != 1 or ins.operands[0].type != ARM_OP_IMM:
        raise ValueError(f"Not a direct branch at {addr:#x}")
    return ins.operands[0].imm


def ascii_at(code, address, max_len=112):
    pos = address - ROM_BASE
    if pos < 0 or pos >= len(code):
        raise ValueError("Out-of-range firmware string")
    s = code[pos:pos+max_len].split(b"\0", 1)[0]
    if not s or not all(32 <= c < 127 or c in (9, 10, 13) for c in s):
        raise ValueError("Expected printable NUL-terminated diagnostic text")
    return s.decode("ascii")


def entry_pointer_contract(code):
    """Confirm exact ARM prologue saves caller-supplied R0 at +0x20."""
    expect(code, ROM_BASE + 0x24, "ldr", "r6, [pc, #0xd0]", thumb=False)
    expect(code, ROM_BASE + 0x28, "str", "r0, [r6]", thumb=False)
    if word(code, ROM_BASE + 0xFC) != ROM_BASE + 0x20:
        raise ValueError("DA2 argument pointer slot literal changed")
    if word(code, ROM_BASE + 0x20) != 0:
        raise ValueError("Expected empty stored-image argument pointer slot")
    expect(code, ROM_BASE + 0xF8, "b", "#0x400000f8", thumb=False)
    return ROM_BASE + 0x20


def verify_binary(e, directory):
    profile = KNOWN[e["filename"]]
    path = directory / e["filename"]
    binary = path.read_bytes()
    if hashlib.sha256(binary).hexdigest() != profile["sha"]:
        raise ValueError("Unexpected stock DA container SHA-256")
    r1, r2 = e["regions"][1], e["regions"][2]
    if r1["address"] != 0x200000 or r2["address"] != ROM_BASE:
        raise ValueError("Unexpected DA1/DA2 load bases")
    da1 = binary[r1["file_offset"]:r1["file_offset"]+r1["bytes"]-r1["signature_bytes"]]
    da2 = binary[r2["file_offset"]:r2["file_offset"]+r2["bytes"]-r2["signature_bytes"]]
    if da1.count(struct.pack("<I", MAGIC_ARGUMENT)) != 1:
        raise ValueError("Expected one exact DA1 argument magic in original body")
    if word(da1, 0x200000+profile["da1_magic"], base=0x200000) != MAGIC_ARGUMENT:
        raise ValueError("DA1 argument magic moved")

    slot = entry_pointer_contract(da2)
    expect(da2, ROM_BASE+0xF4, "blx", thumb=False)
    arm_call = instruction(da2, ROM_BASE+0xF4, thumb=False)
    # ARM-state BLX immediate switches to Thumb; verify the exact target.
    if f"{profile['entry']:#x}" not in arm_call.op_str:
        raise ValueError("DA2 ARM->Thumb kmain jump changed")

    assert_slot = pc_literal(da2, profile["entry"])
    if assert_slot != slot:
        raise ValueError("kmain no longer dereferences saved caller R0")
    expect(da2, profile["entry"]+0x04, "movs",
           f"r2, #{profile['copy_size']:#x}")
    copy_dst_ldr = profile["entry"]+6 if e["filename"].startswith("MTK_DA_V5") else profile["entry"]+6
    if pc_literal(da2, copy_dst_ldr) != profile["copy_dst"]:
        raise ValueError("kmain argument struct destination moved")
    # V5: r1 <- [r4] at +8; alternative: at +8 too.
    expect(da2, profile["entry"]+8, "ldr", "r1, [r4]")
    if branch_target(da2, profile["entry"]+10, "blx") != profile["copy_fn"]:
        raise ValueError("kmain memcpy-style BLX target changed")
    expect(da2, profile["copy_fn"], "cmp", "r2, #0", thumb=False)
    expect(da2, profile["copy_fn"]+4, "cmpne", "r1, r0", thumb=False)
    expect(da2, profile["copy_fn"]+8, "bxeq", "lr", thumb=False)

    thread_ptr = pc_literal(da2, profile["thread_ptr_ldr"])
    if thread_ptr != profile["bootstrap"] | 1:
        raise ValueError("Unexpected bootstrap2 Thumb thread entry")
    if pc_literal(da2, profile["magic_val_ldr"]) != MAGIC_ARGUMENT:
        raise ValueError("Runtime struct argument magic check changed")
    ptr = pc_literal(da2, profile["magic_ptr_ldr"])
    if ptr != profile["copy_dst"]:
        raise ValueError("Bootstrap2 does not check copied arg struct")
    expect(da2, profile["magic_check"], "cmp", "r2, r3")
    if branch_target(da2, profile["halt"], "b") != profile["halt"]:
        raise ValueError("Missing conditional magic mismatch self-loop")
    error_string = ascii_at(da2, pc_literal(da2, profile["error_ldr"]))
    if "bootstrap2 argument magic error. halt." not in error_string:
        raise ValueError("Argument rejection diagnostic mismatched")

    # DA2's ready notification constructs the four-byte SYNC status and
    # dispatches through the actual preinitialized IO function-pointer table.
    if branch_target(da2, profile["ready_call"]) != profile["ready"]:
        raise ValueError("Bootstrap2 ready callback changed")
    if branch_target(da2, profile["command_call"]) != profile["command"]:
        raise ValueError("Bootstrap2 command loop callback changed")
    if pc_literal(da2, profile["ready"]) != SYNC:
        raise ValueError("DA2 did not build literal four-byte SYNC payload")
    expect(da2, profile["ready"]+6, "movs", "r1, #4")
    expect(da2, profile["ready"]+8, "str", "r3, [r0, #-0x4]!")
    io = pc_literal(da2, profile["ready"]+0xC)
    if io != profile["io_table"]:
        raise ValueError("DA2 SYNC I/O function-pointer table changed")
    send_ptr = word(da2, io+4)
    if send_ptr != profile["send_wrapper"] | 1:
        raise ValueError("Expected Thumb-wrapped framed send function")
    if e["filename"].startswith("MTK_DA_V5"):
        # V5 status notifier calls a statistics wrapper, which calls the
        # protocol framing function. This literal lies in the .text pool.
        if branch_target(da2, send_ptr-1+0x10) != profile["frame_sender"]:
            raise ValueError("DA2 V5 framed transport wrapper changed")
        if word(da2, profile["frame_literal"]) != MAGIC_PROTOCOL:
            raise ValueError("DA2 V5 protocol framing magic changed")
        expect(da2, profile["frame_sender"]+0x0C, "movs", "r3, #1")
        expect(da2, profile["frame_sender"]+0x24, "movs", "r1, #0xc")
    else:
        # Alternative send wrapper materializes 0xFEEEEEEF using MOVW/MOVT.
        expect(da2, send_ptr-1+2, "movw", "r3, #0xeeef")
        expect(da2, send_ptr-1+0x12, "movt", "r3, #0xfeee")
        expect(da2, send_ptr-1+0x24, "movs", "r1, #0xc")
    return {
        "loader": e["filename"],
        "da1_argument_magic_offset": hex(profile["da1_magic"]),
        "caller_r0_stored_at": hex(slot),
        "thumb_kernel_entry": hex(profile["entry"]),
        "runtime_parameter_copy_size_bytes": profile["copy_size"],
        "runtime_parameter_copy_destination": hex(profile["copy_dst"]),
        "bootstrap2_thread_entry": hex(profile["bootstrap"]),
        "required_magic": hex(MAGIC_ARGUMENT),
        "on_bad_magic_halts_at": hex(profile["halt"]),
        "usb_sync_status_value": hex(SYNC),
        "ready_notification_entry": hex(profile["ready"]),
        "protocol_frame_magic": hex(MAGIC_PROTOCOL),
        "frame_send_function": hex(profile["frame_sender"]),
        "usb_command_loop_entry": hex(profile["command"]),
    }


def run(directory):
    entries, _, _ = scan_directory(directory)
    records = []
    for e in entries:
        if e["filename"] in KNOWN:
            records.append(verify_binary(e, directory))
    if len(records) != len(KNOWN):
        raise ValueError("Expected both pinned DA1/DA2 loader pairs")
    return records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader_dir", type=Path)
    args = p.parse_args()
    for row in run(args.loader_dir):
        for key, value in row.items():
            print(f"{key}: {value}")
        print()
    print("Static conclusion: a wrong DA1->DA2 runtime argument magic "
          "blocks bootstrap2 before SYNC; the status is framed using XFLASH.")
    print("No evidence yet that this error actually occurs on Crumpet.")
    print("No USB, NAND, firmware writes, DA launch, or proprietary binary export.")


if __name__ == "__main__":
    main()

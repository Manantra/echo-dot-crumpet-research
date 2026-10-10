#!/usr/bin/env python3
"""Read-only validation of the original MT8167 DA1->DA2 argument handoff.

Requires the two *unchanged* MTKClient cd25cf9 DA loader containers, pinned
by full SHA-256. Disassembles original Thumb instruction sites in each DA1,
cross-validates its runtime parameter layout with the verified DA2 argument
copy/magic gate, and reports metadata only. Does NOT run any agent, export
code, upload bytes to a device, write firmware or read NAND.

A static match does NOT establish that real Crumpet RAM/DDR is initialized.
"""
import argparse
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory
from audit_da2_bootstrap_contract import KNOWN, verify_binary

DA1_LOAD_BASE = 0x00200000
DA1_PROFILES = {
    "MTK_DA_V5.bin": {
        "runtime_dst": 0x00239018,
        "magic_instruction": 0x00201512,
        "destination_instruction": 0x00201510,
        "flag_source_instruction": 0x0020151C,
        "flags_extract_instruction": 0x00201520,
        "first_source_instruction": 0x00201514,
        "second_source_instruction": 0x0020152E,
        "first_source": 0x00239150,
        "second_source": 0x002393B8,
        "flag_source": 0x00239308,
        "magic_write_instruction": 0x0020151A,
        "flags_write_instruction": 0x00201524,
        "first_copy": (
            (0x00201526, "ldm", 4), (0x00201528, "stm", 4),
            (0x0020152A, "ldm.w", 2), (0x00201530, "stm.w", 2),
        ),
        "second_copy": (
            (0x00201538, "ldm", 4), (0x0020153A, "stm", 4),
            (0x0020153C, "ldm", 4), (0x0020153E, "stm", 4),
            (0x00201540, "ldm", 4), (0x00201542, "stm", 4),
            (0x00201544, "ldm.w", 2), (0x00201548, "stm.w", 2),
        ),
        "return_pointer_instruction": 0x0020154C,
        "jump_instruction": 0x0020154E,
        "block_register": "r6",
        "jump_register": "r8",
        "first_copy_size": 24,
        "second_copy_size": 56,
        "total": 88,
        "second_dest_instruction": 0x00201534,
    },
    "MTK_AllInOne_DA_mt6590.bin": {
        "runtime_dst": 0x00222A70,
        "magic_instruction": 0x00201008,
        "destination_instruction": 0x00201004,
        "flag_source_instruction": 0x00201014,
        "flags_extract_instruction": 0x00201018,
        "first_source_instruction": 0x0020100A,
        "second_source_instruction": 0x00201028,
        "first_source": 0x00222B88,
        "second_source": 0x00222C50,
        "flag_source": 0x00222C28,
        "magic_write_instruction": 0x00201010,
        "flags_write_instruction": 0x0020101C,
        "first_copy": (
            (0x00201020, "ldm", 4), (0x00201022, "stm", 4),
            (0x00201024, "ldm.w", 2), (0x0020102A, "stm.w", 2),
        ),
        "second_copy": (
            (0x00201032, "ldm", 4), (0x00201034, "stm", 4),
            (0x00201036, "ldm.w", 4), (0x0020103A, "stm.w", 4),
        ),
        "return_pointer_instruction": 0x0020103E,
        "jump_instruction": 0x00201040,
        "block_register": "lr",
        "jump_register": "r7",
        "first_copy_size": 24,
        "second_copy_size": 32,
        "total": 64,
        "second_dest_instruction": 0x0020102E,
    },
}


def thumb_instruction(body, addr):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError as exc:
        raise RuntimeError("Capstone required for static ISA validation") from exc
    pos = addr - DA1_LOAD_BASE
    if pos < 0 or pos + 4 > len(body):
        raise ValueError("Instruction outside DA1 executable")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    ins = list(cs.disasm(body[pos:pos + 4], addr, count=1))
    if len(ins) != 1 or ins[0].address != addr:
        raise ValueError(f"No Thumb instruction at {addr:#x}")
    return ins[0]


def expect_thumb(body, addr, mnemonic, operand_fragment=None):
    i = thumb_instruction(body, addr)
    if i.mnemonic != mnemonic or (
        operand_fragment and operand_fragment not in i.op_str
    ):
        raise ValueError(f"Opcode mismatch @ {addr:#x}: "
                         f"{i.mnemonic} {i.op_str}, expected "
                         f"{mnemonic} {operand_fragment or ''}")
    return i


def thumb_literal(body, address):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    i = thumb_instruction(body, address)
    if (not i.mnemonic.startswith("ldr") or len(i.operands) < 2
            or i.operands[1].type != ARM_OP_MEM
            or i.operands[1].mem.base != ARM_REG_PC):
        raise ValueError(f"Expected Thumb literal LDR at {address:#x}")
    at = ((address + 4) & ~3) + i.operands[1].mem.disp
    offset = at - DA1_LOAD_BASE
    if offset < 0 or offset + 4 > len(body):
        raise ValueError("DA1 constant-pool literal outside executable")
    import struct
    return struct.unpack_from("<I", body, offset)[0]


def transfer_size(body, sequence):
    """Check consecutive LDM/STM register widths, not just total bytes."""
    words_read = 0
    words_written = 0
    for at, mnemonic, count in sequence:
        i = expect_thumb(body, at, mnemonic)
        from capstone.arm import ARM_OP_REG
        # The memory base plus exactly count register operands are required.
        regs = [arg for arg in i.operands if arg.type == ARM_OP_REG]
        if len(regs) != count + 1:
            raise ValueError(f"Bad DA1 {mnemonic} register list @ {at:#x}")
        if mnemonic.startswith("ldm"):
            words_read += count
        elif mnemonic.startswith("stm"):
            words_written += count
        else:
            raise ValueError("Unexpected copy instruction")
    if words_read != words_written:
        raise ValueError("DA1 copy source/destination word counts differ")
    return words_read * 4


def audit_da1(body, profile):
    from audit_da2_bootstrap_contract import MAGIC_ARGUMENT

    lit = {
        "runtime_dst": ("destination_instruction", profile["runtime_dst"]),
        "magic": ("magic_instruction", MAGIC_ARGUMENT),
        "first_source": ("first_source_instruction", profile["first_source"]),
        "second_source": ("second_source_instruction", profile["second_source"]),
        "flag_source": ("flag_source_instruction", profile["flag_source"]),
    }
    for label, (site, expected) in lit.items():
        got = thumb_literal(body, profile[site])
        if got != expected:
            raise ValueError(f"Wrong DA1 {label} constant: "
                             f"{got:#x} != {expected:#x}")

    reg = profile["block_register"]
    expect_thumb(body, profile["magic_write_instruction"],
                 "str" if reg == "r6" else "str.w",
                 f"r3, [{reg}]")
    expect_thumb(body, profile["flags_extract_instruction"],
                 "ubfx", "r3, r3, #1, #1")
    expect_thumb(body, profile["flags_write_instruction"],
                 "str" if reg == "r6" else "str.w",
                 f"r3, [{reg}, #4]")
    offset_first = transfer_size(body, profile["first_copy"])
    offset_second = transfer_size(body, profile["second_copy"])
    if (offset_first != profile["first_copy_size"] or
            offset_second != profile["second_copy_size"] or
            8 + offset_first + offset_second != profile["total"]):
        raise ValueError("Inconsistent DA1 runtime parameter layout")
    # Last group is intentionally placed at offset +0x20 (8+24).
    expected = f"r4, {reg}, #0x20"
    expect_thumb(body, profile["second_dest_instruction"],
                 "add.w", expected)
    expect_thumb(body, profile["return_pointer_instruction"],
                 "mov", f"r0, {reg}")
    expect_thumb(body, profile["jump_instruction"],
                 "blx", profile["jump_register"])
    return {
        "block_vma": hex(profile["runtime_dst"]),
        "header_magic": hex(MAGIC_ARGUMENT),
        "flag_bit": 1,
        "runtime_flag_source_pointer_vma": hex(profile["flag_source"]),
        "first_source_vma": hex(profile["first_source"]),
        "first_copy_bytes": offset_first,
        "second_source_vma": hex(profile["second_source"]),
        "second_copy_bytes": offset_second,
        "total_argument_bytes": profile["total"],
        "final_r0": f"pointer to block ({reg})",
        "indirect_blx_register": profile["jump_register"],
        "source_binary_values_at_these_RAM_addresses": "NOT OBSERVED",
    }


def inspect_loader_pair(loader_dir):
    loader_dir = Path(loader_dir)
    entries, _, _ = scan_directory(loader_dir)
    results = []
    for e in entries:
        name = e["filename"]
        if name not in DA1_PROFILES:
            continue
        full = (loader_dir / name).read_bytes()
        import hashlib
        if hashlib.sha256(full).hexdigest() != KNOWN[name]["sha"]:
            raise ValueError("Unknown full DA container SHA-256; refusing")
        r = e["regions"][1]
        if r["address"] != DA1_LOAD_BASE:
            raise ValueError("Unexpected DA1 load base")
        body = full[r["file_offset"]:
                    r["file_offset"] + r["bytes"] - r["signature_bytes"]]
        data = audit_da1(body, DA1_PROFILES[name])
        da2 = verify_binary(e, loader_dir)
        if da2["runtime_parameter_copy_size_bytes"] != data["total_argument_bytes"]:
            raise ValueError("Paired DA2 expects a different struct length")
        results.append({"container": name,
                        "sha256": KNOWN[name]["sha"],
                        "DA1": data,
                        "DA2_bootstrap_entry": da2["bootstrap2_thread_entry"],
                        "DA2_magic_expected": da2["required_magic"],
                        "DA2_copy_destination": da2[
                            "runtime_parameter_copy_destination"]})
    if len(results) != len(DA1_PROFILES):
        raise ValueError("Expected exactly two pinned MT8167 loader pairs")
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader_dir", type=Path, help="Unchanged local MTKClient Loader/")
    args = p.parse_args()
    for r in inspect_loader_pair(args.loader_dir):
        print("DA CONTAINER", r["container"], "SHA-256", r["sha256"])
        for k, v in r["DA1"].items():
            print(" ", k, "=", v)
        print(" DA2 required magic:", r["DA2_magic_expected"])
        print(" DA2 copy destination:", r["DA2_copy_destination"])
        print(" DA2 bootstrap2 thread entry:", r["DA2_bootstrap_entry"])
    print("All data addresses refer to runtime DA1 RAM; *actual contents* "
          "and jump callback are not observed on any Echo Dot.")
    print("Not proof DA2 executes or bootloader/root can be unlocked.")
    print("No binaries written, USB accessed, or NAND modified.")


if __name__ == "__main__":
    main()

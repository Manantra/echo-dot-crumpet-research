#!/usr/bin/env python3
"""Read-only investigation of mutable DA1 RAM source blocks copied into DA2.

This analyzes exact SHA-256-pinned stock MT8167 DA1 containers from MTKClient
cd25cf9 using Capstone Thumb disassembly; firmware is never run or patched.
The observed addresses refer to *runtime SRAM/BSS*; their contents cannot be
deduced from the static file. Only proven instructions are classified; no USB,
NAND, root operations or proprietary binary redistribution.

This cross-check extends audit_da1_runtime_handoff.py (which proved
8+24+56/32-byte source copies and R0 handoff).
"""
import argparse
import hashlib
import struct
from pathlib import Path

from audit_da1_runtime_handoff import (
    DA1_LOAD_BASE, DA1_PROFILES, expect_thumb,
    thumb_literal, audit_da1
)
from audit_da2_bootstrap_contract import KNOWN
from audit_mtkclient_da_metadata import scan_directory

# Addresses refer ONLY to the pinned originals, not live Crumpet RAM samples.
WRITES = {
    "MTK_DA_V5.bin": (
        (0x2015F6, 0x2015FA, "str", "r2, [r3, #8]", 8),
        (0x201A1E, 0x201A24, "str", "r3, [r4]", 0),
        (0x201A7A, 0x201A7C, "str", "r0, [r3, #0x24]", 0x24),
        (0x202EB6, 0x202EC0, "str", "r2, [r3, #0x10]", 0x10),
        (0x202EB6, 0x202EC2, "str", "r2, [r3, #0x14]", 0x14),
        (0x202EB6, 0x202EC4, "str", "r0, [r3, #0x1c]", 0x1C),
    ),
    "MTK_AllInOne_DA_mt6590.bin": (
        (0x20137A, 0x201382, "str", "r3, [r5, #0x18]", 0x18),
        (0x2014D6, 0x2014D8, "str", "r0, [r3, #0x1c]", 0x1C),
        (0x2025E4, 0x2025EE, "str", "r2, [r3, #0xc]", 0x0C),
        (0x2025E4, 0x2025F2, "str", "r2, [r3, #0x14]", 0x14),
    ),
}

# Reference counts are *literal 32-bit address values*, not proof that
# every occurrence is reached or that all indirect writers are found.
# Only instruction-qualified direct references are called code references.
LITERAL_SITES = {
    "MTK_DA_V5.bin": {
        "first_source_occurrences": 1,
        "second_source_occurrences": 16,
        "first_literal_pc": 0x201514,
        "second_literal_pc": 0x20152E,
        "status_word_pc": 0x20151C,
        "second_state_early_pc": 0x2010DC,
        "second_state_early_insn": 0x2010E2,
    },
    "MTK_AllInOne_DA_mt6590.bin": {
        "first_source_occurrences": 1,
        "second_source_occurrences": 10,
        "first_literal_pc": 0x20100A,
        "second_literal_pc": 0x201028,
        "status_word_pc": 0x201014,
        "second_state_early_pc": 0x20137A,
        "second_state_early_insn": 0x201382,
    },
}


def literal_occurrences(body, address):
    b = struct.pack("<I", address)
    pos = 0
    out = []
    while True:
        offset = body.find(b, pos)
        if offset < 0:
            break
        out.append(offset + DA1_LOAD_BASE)
        pos = offset + 1
    return out


def check_mutable_sources(name, da1):
    if name not in DA1_PROFILES:
        raise ValueError("Unknown DA1 profile")
    prof = DA1_PROFILES[name]
    refs = LITERAL_SITES[name]
    # This verifies the previously established source/copy/jump contract too.
    construction = audit_da1(da1, prof)
    first = prof["first_source"]
    second = prof["second_source"]

    a = literal_occurrences(da1, first)
    b = literal_occurrences(da1, second)
    if len(a) != refs["first_source_occurrences"]:
        raise ValueError("First-source pointer frequency changed")
    if len(b) != refs["second_source_occurrences"]:
        raise ValueError("Mutable second-source pointer frequency changed")
    if thumb_literal(da1, refs["first_literal_pc"]) != first:
        raise ValueError("DA1 first-source instruction no longer references buffer")
    if thumb_literal(da1, refs["second_literal_pc"]) != second:
        raise ValueError("DA1 second-source instruction no longer references buffer")
    if thumb_literal(da1, refs["status_word_pc"]) != prof["flag_source"]:
        raise ValueError("Control status word source changed")
    if thumb_literal(da1, refs["second_state_early_pc"]) != second:
        raise ValueError("Separate early DA1 code no longer accesses state table")
    early = expect_thumb(da1, refs["second_state_early_insn"], "ldr")
    if name.endswith("V5.bin") and "[r3, #8]" not in early.op_str:
        raise ValueError("Early second-source flags field changed")
    if not name.endswith("V5.bin") and "[r5, #0x18]" not in early.op_str:
        raise ValueError("Early alternate second-source field changed")
    proven = []
    for literal_insn, write_insn, mnemonic, operands, field_offset in WRITES[name]:
        if thumb_literal(da1, literal_insn) != second:
            raise ValueError(f"State table pointer changed at {literal_insn:#x}")
        expect_thumb(da1, write_insn, mnemonic, operands)
        if not (0 <= field_offset < prof["second_copy_size"]):
            raise ValueError("State field outside copied second parameter region")
        proven.append({
            "instruction": hex(write_insn),
            "copied_table_field_offset": field_offset,
            "field_vma": hex(second + field_offset),
            "mnemonic": mnemonic,
            "operands": operands,
        })
    return {
        "loader": name,
        "da1_first_source": hex(first),
        "da1_second_mutable_source": hex(second),
        "da1_first_source_literal_occurrences": len(a),
        "da1_second_source_literal_occurrences": len(b),
        "second_source_copied_bytes": prof["second_copy_size"],
        "total_handoff_size": construction["total_argument_bytes"],
        "proven_state_writes": proven,
        "all_indirect_writes_or_runtime_values_found": False,
        "actual_crumpet_ram_contents_observed": False,
    }


def inspect_loader_folder(folder):
    folder = Path(folder)
    entries, _, _ = scan_directory(folder)
    out = []
    for entry in entries:
        name = entry["filename"]
        if name not in DA1_PROFILES:
            continue
        data = (folder / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != KNOWN[name]["sha"]:
            raise ValueError("Unknown DA1 container SHA-256, refusing to infer")
        r = entry["regions"][1]
        if r["address"] != DA1_LOAD_BASE:
            raise ValueError("DA1 load base changed")
        body = data[r["file_offset"]:
                    r["file_offset"] + r["bytes"] - r["signature_bytes"]]
        out.append(check_mutable_sources(name, body))
    if len(out) != len(DA1_PROFILES):
        raise ValueError("Two pinned original MT8167 DA1 loaders required")
    return out


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("original_loader_dir", type=Path)
    args = arg.parse_args()
    for row in inspect_loader_folder(args.original_loader_dir):
        print("LOADER", row["loader"])
        for field in ("da1_first_source", "da1_second_mutable_source",
                      "da1_first_source_literal_occurrences",
                      "da1_second_source_literal_occurrences",
                      "second_source_copied_bytes", "total_handoff_size"):
            print(" ", field, "=", row[field])
        for entry in row["proven_state_writes"]:
            print(" PROVEN DA1 WRITE", entry["instruction"],
                  "field", hex(entry["copied_table_field_offset"]),
                  "original RAM", entry["field_vma"],
                  entry["mnemonic"], entry["operands"])
        print(" ACTUAL LIVE RAM VALUES VERIFIED:", False)
    print("An explicitly updated second DA1 source is copied into DA2. "
          "It is not an immutable compile-time constant or necessarily USB-only.")
    print("Do not infer a Crumpet failure PC, actual runtime callback values, "
          "DA2 execution, or root/unlock from static source analysis.")


if __name__ == "__main__":
    main()

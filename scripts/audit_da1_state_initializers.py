#!/usr/bin/env python3
"""Fail-closed static audit of DA1 default state initializers subsequently copied into DA2.

Requires exact unmodified SHA-256-pinned MT8167 loader containers; no hardware or
binary redistribution. Instruction checks validate *code*, not execution order
or live Crumpet memory. See docs/da1-state-defaults-and-overrides-2026-10-11.md.
"""
import argparse
import hashlib
from pathlib import Path
from audit_da1_runtime_handoff import DA1_PROFILES, DA1_LOAD_BASE, thumb_literal, expect_thumb
from audit_da1_mutable_argument_sources import check_mutable_sources
from audit_da2_bootstrap_contract import KNOWN
from audit_mtkclient_da_metadata import scan_directory

# pc-relative source-pointer instruction, followed by constant-setting stores.
# Each row: instruction address, mnemonic, exact operands, byte field offset.
INITIALIZERS = {
    "MTK_DA_V5.bin": {
        "literal": 0x20254C,
        "writes": (
            (0x20255A, "str", "r2, [r3, #0x10]", 0x10),
            (0x20255C, "str", "r2, [r3, #0x14]", 0x14),
            (0x202562, "str", "r0, [r3, #8]", 8),
            (0x202564, "str", "r2, [r3, #0x18]", 0x18),
            (0x202568, "str", "r0, [r3, #0x28]", 0x28),
            (0x20256A, "str", "r0, [r3, #0x20]", 0x20),
            (0x20256E, "str", "r1, [r3]", 0),
            (0x202570, "str", "r1, [r3, #4]", 4),
            (0x202572, "str", "r0, [r3, #0x24]", 0x24),
            (0x202578, "str", "r2, [r3, #0x2c]", 0x2c),
            (0x20257A, "str", "r2, [r3, #0x30]", 0x30),
        ),
        "constants": (
            (0x20254E, "mov.w", "r2, #0x1000"),
            (0x202552, "movs", "r0, #1"),
            (0x202554, "movs", "r1, #2"),
            (0x20255E, "mov.w", "r2, #0x2000000"),
            (0x202566, "movs", "r2, #0"),
            (0x20256C, "movs", "r0, #0x68"),
        ),
        "revisions": (
            (0x202EC0, "str", "r2, [r3, #0x10]", 0x10),
            (0x202EC2, "str", "r2, [r3, #0x14]", 0x14),
            (0x202EC4, "str", "r0, [r3, #0x1c]", 0x1c),
        ),
        "revision_constant": (0x202EB8, "mov.w", "r2, #0x8000"),
    },
    "MTK_AllInOne_DA_mt6590.bin": {
        "literal": 0x201D48,
        "writes": (
            (0x201D5A, "str", "r2, [r3, #0xc]", 0xc),
            (0x201D60, "str", "r2, [r3, #0x10]", 0x10),
            (0x201D64, "str", "r1, [r3]", 0),
            (0x201D66, "str", "r0, [r3, #8]", 8),
            (0x201D68, "str", "r0, [r3, #0x18]", 0x18),
            (0x201D6A, "str", "r2, [r3, #0x1c]", 0x1c),
            (0x201D6E, "str", "r1, [r3, #4]", 4),
        ),
        "constants": (
            (0x201D4A, "mov.w", "r2, #0x1000"),
            (0x201D50, "movs", "r1, #2"),
            (0x201D52, "movs", "r0, #1"),
            (0x201D5C, "mov.w", "r2, #0x2000000"),
            (0x201D62, "movs", "r2, #0x68"),
        ),
        "revisions": (
            (0x2025EE, "str", "r2, [r3, #0xc]", 0xc),
            (0x2025F2, "str", "r2, [r3, #0x14]", 0x14),
        ),
        "revision_constant": (0x2025E6, "mov.w", "r2, #0x8000"),
    },
}

def validate_offsets(writes, copied_bytes):
    """Check field bounds and 32-bit alignment, rejecting duplicated write sites."""
    sites = set()
    for address, _mnemonic, _operands, offset in writes:
        if address in sites:
            raise ValueError("Repeated write instruction")
        sites.add(address)
        if offset < 0 or offset % 4 or offset + 4 > copied_bytes:
            raise ValueError("Field outside aligned copied source region")
    return len(writes)

def audit_defaults(name, da1):
    if name not in INITIALIZERS:
        raise ValueError("Unknown DA1 profile")
    # Also re-check full previously demonstrated DA1 runtime ABI and field mutations.
    original = check_mutable_sources(name, da1)
    layout = INITIALIZERS[name]
    source = DA1_PROFILES[name]["second_source"]
    size = DA1_PROFILES[name]["second_copy_size"]
    if thumb_literal(da1, layout["literal"]) != source:
        raise ValueError("Initializer not pointing to transferred source table")
    for address, mnemonic, operands in layout["constants"]:
        expect_thumb(da1, address, mnemonic, operands)
    for address, mnemonic, operands, _offset in layout["writes"]:
        expect_thumb(da1, address, mnemonic, operands)
    validate_offsets(layout["writes"], size)
    # Separate later routine also addresses the same structure via a literal load.
    from audit_da1_mutable_argument_sources import WRITES
    revision_pointer = WRITES[name][-1][0]
    if thumb_literal(da1, revision_pointer) != source:
        raise ValueError("Revision routine not pointing to transferred source")
    caddr, cmn, cops = layout["revision_constant"]
    expect_thumb(da1, caddr, cmn, cops)
    for address, mnemonic, operands, _offset in layout["revisions"]:
        expect_thumb(da1, address, mnemonic, operands)
    validate_offsets(layout["revisions"], size)
    return {"loader": name, "runtime_second_source": hex(source),
            "initializer_field_stores": len(layout["writes"]),
            "additional_revision_stores": len(layout["revisions"]),
            "initializer_entry": hex(layout["literal"]),
            "additional_revision_entry": hex(revision_pointer),
            "live_values_observed": False,
            "matched_copy_bytes": original["second_source_copied_bytes"]}

def audit_folder(path):
    entries, _, _ = scan_directory(path)
    results = []
    for entry in entries:
        name = entry["filename"]
        if name not in INITIALIZERS:
            continue
        data = (path / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != KNOWN[name]["sha"]:
            raise ValueError("Unrecognized original DA container")
        region = entry["regions"][1]
        if region["address"] != DA1_LOAD_BASE:
            raise ValueError("Unexpected DA1 load address")
        body = data[region["file_offset"]:
                    region["file_offset"] + region["bytes"] - region["signature_bytes"]]
        results.append(audit_defaults(name, body))
    if len(results) != 2:
        raise ValueError("Both exact MT8167 originals required")
    return results

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("original_loader_dir", type=Path)
    args = ap.parse_args()
    for row in audit_folder(args.original_loader_dir):
        print(row)
    print("Static initializers and later stores, NOT observed Crumpet execution or root.")

if __name__ == "__main__":
    main()

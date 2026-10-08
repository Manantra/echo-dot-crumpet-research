#!/usr/bin/env python3
"""Offline audit of the published Crumpet amonet preloader patch addresses.

Matches the public devices/crumpet.c patch-site constants to the *stored-file*
MediaTek GFH/FILE_INFO load-address mapping from an existing, local Crumpet
preloader image. Checks whether the original patch helper writes unadjusted
absolute addresses, and reports read-only disassembly/ASCII context.

This DOES NOT patch firmware, build an exploit, communicate with devices,
write storage or establish that the runtime RAM mapping is unchanged.
"""
import argparse
import hashlib
import re
from pathlib import Path

from disassemble_preloader import address_to_offset, locate_image

PATCH_RE = re.compile(
    r"(?m)^\s*(patch_ret|patch_word|patch_branch)\(\s*(0x[0-9a-fA-F]+)\s*,"
)


def parse_patch_sites(source):
    out = []
    for match in PATCH_RE.finditer(source):
        operation, address_text = match.groups()
        out.append({"operation": operation, "address": int(address_text, 16)})
    if not out:
        raise ValueError("No Crumpet patch-site calls found")
    addrs = [x["address"] for x in out]
    if len(set(addrs)) != len(addrs):
        raise ValueError("Duplicate patch-site address")
    return out


def confirm_unadjusted_patch_writer(source):
    if not re.search(
        r"void\s+patch_word\s*\(\s*uint32_t\s+addr,\s*uint32_t\s+value\s*\)\s*"
        r"\{\s*writel\s*\(\s*value,\s*addr\s*\)", source
    ):
        raise ValueError("Direct patch_word() address semantics not confirmed")
    if not re.search(r"patch_word\s*\(\s*addr,\s*.*?\)", source):
        raise ValueError("No patch_ret → patch_word use confirmed")
    if not re.search(r"writew\s*\([^;]*,\s*addr\s*\)", source):
        raise ValueError("No halfword branch-patch write to absolute addr confirmed")
    return True


def nearby_ascii_sequences(data, offset, margin=40):
    """Locate printable runs near the target; offsets never imply code/data truth."""
    start = max(0, offset - margin)
    stop = min(len(data), offset + margin + 16)
    sequences = []
    for found in re.finditer(rb"[ -~]{8,}", data[start:stop]):
        candidate = found.group()
        # Executable Thumb bytes can accidentally form 8-byte printable
        # runs. Require a longer phrase with spaces and alphabetic content
        # before calling it human-readable, and still mark as a heuristic.
        if not (len(candidate) >= 12 and b" " in candidate and
                sum(65 <= byte <= 90 or 97 <= byte <= 122
                    for byte in candidate) >= 6):
            continue
        lo, hi = start + found.start(), start + found.end()
        if lo - 4 <= offset <= hi + 4:
            sequences.append({
                "starts_at": lo,
                "contains_site": lo <= offset < hi,
                "text": found.group()[:100].decode("ascii"),
            })
    return sequences


def audit_image(data, sites, decode_thumb=True):
    entry, load = locate_image(data)
    decoder = None
    if decode_thumb:
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
            decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        except ImportError:
            decoder = None

    checks = []
    for site in sites:
        addr = site["address"]
        offset = address_to_offset(data, addr, 32)
        raw = data[offset:offset + 32]
        decoded = []
        if decoder:
            decoded = [(ins.mnemonic, ins.op_str) for ins in
                       list(decoder.disasm(raw, addr))[:6]]
        ascii_near = nearby_ascii_sequences(data, offset)
        checks.append({
            **site, "offset": offset,
            "first_4_bytes": raw[:4].hex(),
            "nearby_printable": ascii_near,
            "thumb_first_instructions": decoded,
        })
    return {"encoded_load": load, "entry_offset": entry,
            "image_sha256": hashlib.sha256(data).hexdigest(), "sites": checks}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("crumpet_c", type=Path,
                   help="Downloaded public amonet/devices/crumpet.c source")
    p.add_argument("patch_c", type=Path,
                   help="Downloaded public amonet/patch.c source")
    p.add_argument("preloader_images", type=Path, nargs="+",
                   help="Already obtained LOCAL public/archive Crumpet boot images")
    args = p.parse_args()
    src = args.crumpet_c.read_text(encoding="utf-8")
    implementation = args.patch_c.read_text(encoding="utf-8")
    confirm_unadjusted_patch_writer(implementation)
    sites = parse_patch_sites(src)
    print("Read-only Crumpet amonet absolute-address audit")
    print("Patch writer: direct RAM writes, NO version-dependent remapping")
    for path in args.preloader_images:
        data = path.read_bytes()
        try:
            result = audit_image(data, sites)
        except ValueError as exc:
            print(f"\n{path.name}: INCOMPATIBLE FORMAT / RANGE: {exc}")
            continue
        print(f"\n{path.name}: SHA256 {result['image_sha256']}")
        print(f"  GFH-mapped entry={result['entry_offset']:#x}, "
              f"encoded_load={result['encoded_load']:#x}")
        for x in result["sites"]:
            print(f"  {x['operation']} at {x['address']:#010x}: "
                  f"stored offset {x['offset']:#x}, first 4 bytes "
                  f"{x['first_4_bytes']}")
            for info in x["nearby_printable"]:
                print("    Plausible ASCII context (heuristic):", repr(info["text"][:72]),
                      "[SITE WITHIN PRINTABLE SPAN]" if info["contains_site"] else
                      "[SITE CLOSE TO PRINTABLE SPAN]")
            if x["thumb_first_instructions"]:
                print("    Thumb decoding from site:",
                      " | ".join(f"{op} {args}" for op, args in
                                 x["thumb_first_instructions"][:4]))
    print("\nThese are stored-image offsets only: not proof of in-RAM layout.")
    print("Disassembly may start in the middle of a Thumb instruction or literal.")
    print("No function identity established solely from valid Thumb decoding.")
    print("This tool never edits files or device security state.")


if __name__ == "__main__":
    main()

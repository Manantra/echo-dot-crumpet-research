#!/usr/bin/env python3
"""Audit pinned MT8167 DA1 Stage-2 SHA-1 acceptance and the host log gate.

Uses only original stock MTKClient cd25cf9 loader files and Python source.
No agent upload, USB, real-device DRAM access, NAND read/write or patch.
A patched-at-runtime agent may differ from these verified stock binaries.
"""
import argparse
import ast
import hashlib
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory
from audit_da2_bootstrap_contract import KNOWN
from audit_da1_runtime_handoff import (
    DA1_LOAD_BASE, expect_thumb, thumb_literal,
)

TARGETS = {
    "MTK_DA_V5.bin": {
        "expected_sha1_addr": 0x0021A134,
        "checksum_compare": 0x002014A2,
        "checksum_loop": 0x00201494,
        "mismatch_code_load": 0x002014C8,
        "mismatch_code_store": 0x002014CA,
        "status_callback_load": 0x002014F4,
        "status_callback_call": 0x002014FA,
        "status_signed_check": 0x002014FE,
        "jump_pointer_mov": 0x0020154C,
        "jump_call": 0x0020154E,
        "failure_code": 0xC0070004,
    },
    "MTK_AllInOne_DA_mt6590.bin": {
        "expected_sha1_addr": 0x00221A58,
        "checksum_compare": 0x00200FBA,
        "checksum_loop": 0x00200FB0,
        "mismatch_code_load": 0x00200FDE,
        "mismatch_code_store": 0x00200FE0,
        "status_callback_load": 0x00200FE8,
        "status_callback_call": 0x00200FEE,
        "status_signed_check": 0x00200FF2,
        "jump_pointer_mov": 0x0020103E,
        "jump_call": 0x00201040,
        "failure_code": 0xC0070004,
    }
}


def compare_sha1(expected, da2_executable_body):
    if len(expected) != 20:
        raise ValueError("Expected exactly 20 bytes for SHA-1")
    return expected == hashlib.sha1(da2_executable_body).digest()


def validate_binary_pair(entry, directory):
    name = entry["filename"]
    if name not in TARGETS:
        raise ValueError("Unsupported DA pair")
    profile = TARGETS[name]
    container = (directory / name).read_bytes()
    if hashlib.sha256(container).hexdigest() != KNOWN[name]["sha"]:
        raise ValueError("Unrecognized entire stock DA container SHA-256")
    r1, r2 = entry["regions"][1:3]
    if r1["address"] != DA1_LOAD_BASE or r2["address"] != 0x40000000:
        raise ValueError("Unexpected DA1 or DA2 load address")
    def executable(r):
        start = r["file_offset"]
        nbytes = r["bytes"] - r["signature_bytes"]
        if nbytes <= 0 or start < 0 or start + r["bytes"] > len(container):
            raise ValueError("Unexpected DA executable/signature size")
        return container[start:start + nbytes]
    da1, da2 = executable(r1), executable(r2)
    off = profile["expected_sha1_addr"] - DA1_LOAD_BASE
    expected = da1[off:off+20]
    if len(expected) != 20 or not compare_sha1(expected, da2):
        raise ValueError("Stock DA1 embedded SHA-1 does not match paired DA2")

    expect_thumb(da1, profile["checksum_compare"], "cmp", "r1, r2")
    expect_thumb(da1, profile["mismatch_code_store"], "str",
                 "r3, [sp, #4]" if "V5" in name
                 else "r3, [sp, #8]")
    if thumb_literal(da1, profile["mismatch_code_load"]) != profile["failure_code"]:
        raise ValueError("Hash mismatch protocol status literal changed")
    cbreg = "r7" if "V5" in name else "r6"
    expect_thumb(da1, profile["status_callback_load"],
                 "ldr", f"r3, [{cbreg}, #4]")
    expect_thumb(da1, profile["status_callback_call"], "blx", "r3")
    expect_thumb(da1, profile["status_signed_check"], "cmp", "r0, #0")
    expect_thumb(da1, profile["jump_pointer_mov"], "mov",
                 "r0, r6" if "V5" in name else "r0, lr")
    expect_thumb(da1, profile["jump_call"], "blx",
                 "r8" if "V5" in name else "r7")
    return {
        "pair": name,
        "container_sha256": KNOWN[name]["sha"],
        "embedded_da2_sha1_vma": hex(profile["expected_sha1_addr"]),
        "embedded_da2_sha1": expected.hex(),
        "actual_stock_da2_executable_sha1": hashlib.sha1(da2).hexdigest(),
        "digest_matches": True,
        "da1_compare_instruction": hex(profile["checksum_compare"]),
        "sha1_failure_status": hex(profile["failure_code"]),
        "mismatch_status_store": hex(profile["mismatch_code_store"]),
        "status_callback": hex(profile["status_callback_call"]),
        "r0_pointer_jump": hex(profile["jump_call"]),
    }


def host_gate(source):
    """Validate original host's 'accepted' log is gated by status==0.

    Checks AST, not text occurrence; this does not guarantee a physical
    device status response, nor detect all possible transport corruption.
    """
    parsed = ast.parse(source)
    cls = [n for n in parsed.body
           if isinstance(n, ast.ClassDef) and n.name == "DAXFlash"]
    if len(cls) != 1:
        raise ValueError("Missing or ambiguous original DAXFlash class")

    def method(name):
        found = [n for n in cls[0].body
                 if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(found) != 1:
            raise ValueError(f"Missing original {name}")
        return found[0]
    sender, starter = method("send_data"), method("boot_to")
    # A conditional return True must be guarded by exactly 'status == 0'.
    success = [
        n for n in ast.walk(sender)
        if isinstance(n, ast.If)
        and isinstance(n.test, ast.Compare)
        and isinstance(n.test.left, ast.Name)
        and n.test.left.id == "status"
        and len(n.test.ops) == 1
        and isinstance(n.test.ops[0], ast.Eq)
        and len(n.test.comparators) == 1
        and isinstance(n.test.comparators[0], ast.Constant)
        and n.test.comparators[0].value == 0
        and any(isinstance(ret, ast.Return)
                and isinstance(ret.value, ast.Constant)
                and ret.value.value is True
                for s in n.body for ret in ast.walk(s))
    ]
    if len(success) != 1:
        raise ValueError("No original status==0 send_data success gate")
    if not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "status"
        for n in ast.walk(sender)):
        raise ValueError("send_data does not consult framed status")

    sends = [n for n in ast.walk(starter)
             if isinstance(n, ast.If)
             and isinstance(n.test, ast.Call)
             and isinstance(n.test.func, ast.Attribute)
             and n.test.func.attr == "send_data"]
    if len(sends) != 1:
        raise ValueError("boot_to no longer has one send_data true branch")
    success_strings = [
        n.value for statement in sends[0].body for n in ast.walk(statement)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and "Upload data was accepted. Jumping to stage 2" in n.value
    ]
    if len(success_strings) != 1:
        raise ValueError("Accepted log not under send_data success gate")
    if not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "status"
        for statement in sends[0].body for n in ast.walk(statement)):
        raise ValueError("No later Stage-2 status read after accepted message")
    return {
        "log_only_after_da_data_status_zero": True,
        "further_da2_status_read_after_accepted": True,
        "stock_da1_error_status": "0xC0070004",
        "meaning_of_accepted": "pre-jump DA transfer acknowledged, NOT DA2 execution",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("loader_dir", type=Path)
    ap.add_argument("xflash_source", type=Path)
    args = ap.parse_args()
    entries, _, _ = scan_directory(args.loader_dir)
    verified = [validate_binary_pair(e, args.loader_dir) for e in entries
                if e["filename"] in TARGETS]
    if len(verified) != len(TARGETS):
        raise ValueError("Need both unmodified pinned original DA pairs")
    for r in verified:
        for k, v in r.items():
            print(k, "=", v)
        print()
    for k, v in host_gate(args.xflash_source.read_text(encoding="utf-8")).items():
        print(k, "=", v)
    print("Code pairing and host acknowledgment are verified statically.")
    print("No proof about in-memory patched agents, actual Crumpet DA2, or root.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Statically audit MTKClient DA1 setup result checks and connection-mode paths.

Reads a LOCAL upstream source file, never imports or executes its code, and
never contacts USB or invokes an exploit. Useful to catch source changes to
the specific diagnostic behavior observed in MTKClient cd25cf9.
"""
import argparse
import ast
from pathlib import Path

SETUP_CALLS = ("sync", "setup_env", "setup_hw_init")


def get_method(tree, name):
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name == "DAXFlash"), None)
    if cls is None:
        raise ValueError("Class DAXFlash not found")
    result = next((n for n in cls.body
                   if isinstance(n, ast.FunctionDef) and n.name == name), None)
    if result is None:
        raise ValueError(f"Method DAXFlash.{name} missing")
    return result


def direct_self_call(node, name):
    return (isinstance(node, ast.Expr) and
            isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and
            isinstance(node.value.func.value, ast.Name) and
            node.value.func.value.id == "self" and
            node.value.func.attr == name)


def calls_method(tree, name):
    return any(isinstance(c, ast.Call) and
               isinstance(c.func, ast.Attribute) and
               isinstance(c.func.value, ast.Name) and
               c.func.value.id == "self" and
               c.func.attr == name for c in ast.walk(tree))


def match_connagent(node, expected):
    return (isinstance(node, ast.Compare) and
            isinstance(node.left, ast.Name) and node.left.id == "connagent" and
            len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq) and
            len(node.comparators) == 1 and
            isinstance(node.comparators[0], ast.Constant) and
            node.comparators[0].value == expected)


def inspect_source(source):
    tree = ast.parse(source)
    upload1 = get_method(tree, "upload_da1")
    upload2 = get_method(tree, "upload_da")
    ignored = {name: any(direct_self_call(n, name) for n in ast.walk(upload1))
               for name in SETUP_CALLS}

    # This source-code diagnostic intentionally reports an unchecked call,
    # not that a failed call *necessarily* occurs on real hardware.
    if not all(ignored.values()):
        raise ValueError("Expected unchecked setup calls have changed; re-audit source")

    if not any(calls_method(n, "xread") for n in ast.walk(upload1)):
        raise ValueError("Expected Stage-1 XFLASH final response check not found")
    if not (calls_method(upload2, "upload_da1") and
            calls_method(upload2, "boot_to")):
        raise ValueError("Expected two-stage upload flow missing")

    branches = {}
    for n in ast.walk(upload2):
        if isinstance(n, ast.If) and match_connagent(n.test, b"brom"):
            branches["brom"] = n
            if n.orelse and len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If):
                if match_connagent(n.orelse[0].test, b"preloader"):
                    branches["preloader"] = n.orelse[0]
            break
    if "brom" not in branches or "preloader" not in branches:
        raise ValueError("Expected BROM/Preloader connection branches missing")
    brom_emi = calls_method(branches["brom"], "send_emi")
    # Narrow the preloader branch body itself; do not include its sibling
    # normal stage-2 launch paths.
    preloader_emi = any(calls_method(n, "send_emi")
                        for n in branches["preloader"].body)
    if not brom_emi or preloader_emi:
        raise ValueError("BROM/preloader EMI handling differs from pinned source")
    return {"unchecked_setup_results": ignored, "brom_explicit_emi": brom_emi,
            "preloader_explicit_emi": preloader_emi,
            "both_call_stage2": calls_method(upload2, "boot_to")}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xflash_source", type=Path,
                   help="Path to LOCAL mtkclient/Library/DA/xflash/xflash_lib.py")
    a = p.parse_args()
    summary = inspect_source(a.xflash_source.read_text(encoding="utf-8"))
    print("READ-ONLY AST audit of original MTKClient source")
    for item, value in summary["unchecked_setup_results"].items():
        print(f"  DA1 setup call {item}(): result is not checked = {value}")
    print("  BROM sends external EMI via Stage 1:", summary["brom_explicit_emi"])
    print("  Preloader sends external EMI via Stage 1:", summary["preloader_explicit_emi"])
    print("  Stage 2 uses common boot_to():", summary["both_call_stage2"])
    print("An unchecked return value is a host diagnostic limitation.")
    print("This tool does not prove any DA1 setup failure occurred on Crumpet.")


if __name__ == "__main__":
    main()

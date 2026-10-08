#!/usr/bin/env python3
"""Read-only AST audit of MTKClient XFLASH Stage-2 and USB failure paths.

Reads local upstream Python source and classifies manufactured status bytes.
Never imports MTKClient, executes DA code, or uses USB/device storage.
"""
import argparse
import ast
import struct
from pathlib import Path

MAGIC = 0xFEEEEEEF
ACCEPTED = (0, 0x434E5953)


def method_from_file(text, cls, name):
    tree = ast.parse(text)
    definitions = [n for n in tree.body if isinstance(n, ast.ClassDef)
                   and n.name == cls]
    if len(definitions) != 1:
        raise ValueError(f"Expected one class {cls}")
    methods = [n for n in definitions[0].body
               if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(methods) != 1:
        raise ValueError(f"Expected one method {cls}.{name}")
    return methods[0]


def walk_calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def call_tail(c):
    f = c.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def method_audit(xflash_source, usb_source):
    boot = method_from_file(xflash_source, "DAXFlash", "boot_to")
    status = method_from_file(xflash_source, "DAXFlash", "status")
    send = method_from_file(xflash_source, "DAXFlash", "send_data")
    upload = method_from_file(xflash_source, "DAXFlash", "upload_da")
    reinit = method_from_file(xflash_source, "DAXFlash", "reinit")
    read = method_from_file(usb_source, "UsbClass", "usbread")
    broad_except = any(
        isinstance(n, ast.ExceptHandler) and isinstance(n.type, ast.Name)
        and n.type.id == "Exception" for n in ast.walk(boot))
    generic_dram = any(
        isinstance(n, ast.Constant) and isinstance(n.value, str)
        and "Stage was't executed. Maybe dram issue" in n.value
        for n in ast.walk(boot))
    boot_has_sleep = any(
        isinstance(c.func, ast.Attribute)
        and isinstance(c.func.value, ast.Name)
        and c.func.value.id == "time" and c.func.attr == "sleep"
        and c.args and isinstance(c.args[0], ast.Name)
        and c.args[0].id == "timeout" for c in walk_calls(boot))
    no_read_timeout_arg = not any(
        call_tail(c) in ("usbread", "status") and any(
            kw.arg in ("timeout", "maxtimeout") for kw in c.keywords)
        for c in walk_calls(boot))

    loops = [n for n in ast.walk(send) if isinstance(n, ast.While)]
    if len(loops) != 1:
        raise ValueError("Expected exactly one send_data write loop")
    loop = loops[0]
    if not (isinstance(loop.test, ast.Compare)
            and isinstance(loop.test.left, ast.Name)
            and loop.test.left.id == "bytestowrite"
            and isinstance(loop.test.ops[0], ast.Gt)):
        raise ValueError("Unexpected DA2 send-loop termination")
    guarded_write = any(
        isinstance(n, ast.If)
        and any(call_tail(c) == "usbwrite" for c in walk_calls(n.test))
        and any(isinstance(st, ast.AugAssign)
                and isinstance(st.target, ast.Name)
                and st.target.id == "bytestowrite" for st in n.body)
        and not n.orelse for n in loop.body)
    loop_exits = any(isinstance(n, (ast.Break, ast.Return))
                     for st in loop.body for n in ast.walk(st))
    upload_calls = [call_tail(c) for c in walk_calls(upload)]
    reinit_calls = [call_tail(c) for c in walk_calls(reinit)]
    try:
        boot_index = upload_calls.index("boot_to")
        reinit_index = upload_calls.index("reinit")
    except ValueError as exc:
        raise ValueError("Expected Stage-2 boot_to and reinit") from exc
    reconnect_in_reinit = all(n in reinit_calls for n in ("close", "connect"))
    read_defaults = dict(zip(
        (a.arg for a in read.args.args[-len(read.args.defaults):]),
        (d.value if isinstance(d, ast.Constant) else None
         for d in read.args.defaults)))
    usb_read_returns_empty = any(
        isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
        and n.value.value == b"" for n in ast.walk(read))
    status_calls = [call_tail(c) for c in walk_calls(status)]
    if "unpack" not in status_calls or "usbread" not in status_calls:
        raise ValueError("XFLASH status no longer parses a USB frame")
    return {
        "boot_exception_mapped_to_generic_dram_line":
            broad_except and generic_dram,
        "boot_timeout_controls_sleep_not_usb_read":
            boot_has_sleep and no_read_timeout_arg,
        "send_data_can_spin_after_usbwrite_false":
            guarded_write and not loop_exits,
        "usbread_default_max_timeout_retries":
            read_defaults.get("maxtimeout"),
        "usbread_can_return_empty":
            usb_read_returns_empty,
        "stage2_reconnect_deferred_until_after_boot_success":
            boot_index < reinit_index and reconnect_in_reinit,
    }


def classify_status_reply(header, payload=b""):
    """Model the pinned MTKClient status plus Stage-2 boot decision.

    Inputs are manufactured bytes; no actual transport calls.
    """
    try:
        magic, _, length = struct.unpack("<III", header)
    except struct.error:
        return "EXCEPTION_SHORT_HEADER__GENERIC_DRAM_LINE"
    if magic != MAGIC:
        return "NEGATIVE_ONE_WRONG_MAGIC__NO_GENERIC_DRAM_LINE"
    if length > 4096:
        return "OUT_OF_SCOPE_LARGE_LENGTH"
    if len(payload) < length:
        return "NEGATIVE_ONE_SHORT_PAYLOAD__NO_GENERIC_DRAM_LINE"
    try:
        if length == 2:
            code = struct.unpack("<H", payload[:2])[0]
        elif length == 4:
            code = struct.unpack("<I", payload[:4])[0]
            if code == MAGIC:
                code = 0
        else:
            code = struct.unpack("<" + str(length // 4) + "I",
                                 payload[:length])[0]
    except (struct.error, IndexError):
        return "EXCEPTION_MALFORMED_LENGTH__GENERIC_DRAM_LINE"
    if code in ACCEPTED:
        return "STATUS_SUCCESS"
    return f"STATUS_EXPLICIT_ERROR_0x{code:08X}__NO_GENERIC_DRAM_LINE"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xflash_py", type=Path)
    p.add_argument("usb_lib_py", type=Path)
    args = p.parse_args()
    result = method_audit(args.xflash_py.read_text(encoding="utf-8"),
                          args.usb_lib_py.read_text(encoding="utf-8"))
    for k, v in result.items():
        print(f"{k}: {v}")
    print("In-memory simulated reply classifications (NOT hardware observations):")
    for label, head, body in (
        ("empty header", b"", b""),
        ("short header", bytes(4), b""),
        ("short body", struct.pack("<III", MAGIC, 1, 4), b""),
        ("success zero", struct.pack("<III", MAGIC, 1, 4), struct.pack("<I", 0)),
        ("success SYNC", struct.pack("<III", MAGIC, 1, 4),
         struct.pack("<I", 0x434E5953)),
        ("explicit status", struct.pack("<III", MAGIC, 1, 4),
         struct.pack("<I", 0xC0050005)),
        ("wrong magic", struct.pack("<III", 0x12345678, 1, 4),
         struct.pack("<I", 0)),
    ):
        print(f"  {label}: {classify_status_reply(head, body)}")
    print("No root cause follows from the generic DRAM line alone.")
    print("No imports of MTKClient or real USB traffic.")


if __name__ == "__main__":
    main()

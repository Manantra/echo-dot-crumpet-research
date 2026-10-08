#!/usr/bin/env python3
"""Decode ONLY a previously captured MTKClient XFLASH status frame.

The MTKClient source calls usbread(12), expects a 12-byte header beginning
0xFEEEEEEF, then reads a length-specified little-endian payload.
This program never opens USB/serial ports, sends commands, patches Download
Agents, or modifies devices. Input is a short saved status *response*.
"""
import argparse
import struct
from pathlib import Path

MAGIC = 0xFEEEEEEF
MAX_STATUS = 1024
BOOTTOSUCCESS = 0x434E5953  # "SYNC" in little-endian byte order


def decode_frame(raw):
    if len(raw) < 12:
        return {
            "state": "short_header",
            "message": f"Only {len(raw)} of 12 header bytes captured. "
                       "MTKClient status() may throw unpack error; cause unknown.",
        }
    magic, data_type, length = struct.unpack_from("<III", raw, 0)
    if magic != MAGIC:
        return {
            "state": "wrong_magic", "data_type": data_type,
            "message": f"Wrong protocol magic: {magic:#010x}. "
                       "MTKClient status() returns -1, not a diagnosed DRAM error.",
        }
    if length > MAX_STATUS:
        return {
            "state": "invalid_length", "data_type": data_type,
            "message": f"Unreasonable frame payload length {length}; "
                       "do not attempt to allocate/read an unbounded payload.",
        }
    if len(raw) < 12 + length:
        return {
            "state": "short_payload", "data_type": data_type,
            "message": f"Only {len(raw)-12} of {length} status bytes captured. "
                       "A transport timeout or malformed response is possible.",
        }
    if length == 0:
        return {
            "state": "empty_payload", "data_type": data_type,
            "message": "No status bytes. MTKClient may throw while unpacking.",
        }
    payload = raw[12:12 + length]
    if length == 2:
        status = struct.unpack_from("<H", payload)[0]
    elif length >= 4 and length % 4 == 0:
        status = struct.unpack_from("<I", payload)[0]
    else:
        return {
            "state": "unsupported_length", "data_type": data_type,
            "message": f"Payload length {length} is not a supported status layout.",
        }
    if status == MAGIC:
        # Current MTKClient normalizes this four-byte response to zero.
        status = 0
    boot_success = status in (0, BOOTTOSUCCESS)
    return {
        "state": "complete", "data_type": data_type, "status": status,
        "boot_to_success": boot_success,
        "message": ("Success/status accepted in MTKClient boot_to()"
                    if boot_success
                    else "Non-success status returned; this is not an exception."),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex", dest="hexdata",
                   help="Hexadecimal bytes from a SAVED/authorized response (spaces allowed)")
    g.add_argument("--file", type=Path,
                   help="Previously saved small binary response frame (no device access)")
    args = p.parse_args()
    if args.hexdata is not None:
        raw = bytes.fromhex(args.hexdata)
    else:
        if args.file.stat().st_size > MAX_STATUS + 12:
            p.error("File exceeds the maximum permitted status-frame size")
        raw = args.file.read_bytes()
    if len(raw) > MAX_STATUS + 12:
        p.error("Input exceeds the maximum permitted status-frame size")
    result = decode_frame(raw)
    print("Read-only MTKClient XFLASH status-frame interpretation:")
    for key, value in result.items():
        print(f"  {key}: {value}")
    print("A valid frame proves neither NAND access nor root. "
          "A missing response cannot identify the crash cause.")


if __name__ == "__main__":
    main()

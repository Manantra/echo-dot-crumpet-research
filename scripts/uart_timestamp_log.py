#!/usr/bin/env python3
"""Passive UART logger that stamps each line with host wall-clock time.

Only reads from the serial port; it never writes to it. Saves the exact
received bytes (<prefix>.raw) and a text copy with the host time at which each
line started (<prefix>.txt), so the log can be lined up with USB or hub logs.

The output contains device identifiers. Keep it outside the repository and
run redact_uart_log.py on a copy before sharing any part of it.
"""
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path


def stamp(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def printable(raw):
    return "".join(chr(b) if 32 <= b < 127 or b == 9 else "." for b in raw)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", default="COM3")
    p.add_argument("--baud", type=int, default=921600)
    p.add_argument("--out-dir", type=Path, required=True,
                   help="Existing directory outside the repository")
    p.add_argument("--name", default="uart", help="File name prefix")
    p.add_argument("--seconds", type=float, help="Stop after this many seconds")
    p.add_argument("--echo", action="store_true", help="Also print lines to the console")
    args = p.parse_args(argv)

    if not args.out_dir.is_dir():
        p.error(f"not a directory: {args.out_dir}")
    base = args.out_dir / f"{args.name}_{datetime.now():%H%M%S}_{args.baud}"
    raw_path, txt_path = base.with_suffix(".raw"), base.with_suffix(".txt")

    import serial
    port = serial.Serial(args.port, args.baud, timeout=0.05)
    start = time.time()
    line, line_ts, total = bytearray(), None, 0
    print(f"Logging {args.port} @ {args.baud} to {txt_path} (Ctrl+C to stop)", flush=True)
    try:
        with open(raw_path, "xb") as raw, open(txt_path, "x", encoding="ascii") as txt:
            txt.write(f"# start {stamp(start)} port={args.port} baud={args.baud}\n")
            while args.seconds is None or time.time() - start < args.seconds:
                chunk = port.read(4096)
                if not chunk:
                    continue
                now = time.time()
                raw.write(chunk)
                raw.flush()
                total += len(chunk)
                for b in chunk:
                    if line_ts is None:
                        line_ts = now
                    if b == 0x0A:
                        text = printable(bytes(line).rstrip(b"\r"))
                        out = f"{stamp(line_ts)} | {text}"
                        txt.write(out + "\n")
                        if args.echo:
                            print(out, flush=True)
                        line, line_ts = bytearray(), None
                    else:
                        line.append(b)
                txt.flush()
    except KeyboardInterrupt:
        pass
    finally:
        port.close()
    print(f"Stopped after {time.time() - start:.1f}s, {total} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

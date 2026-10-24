#!/usr/bin/env python3
"""
UART TX probe for Crumpet boot console detection.

Monitors COM3 across multiple power cycles. Detects boot phases by the
binary→ASCII transition, then sends probe sequences during the LK window to
test for an interactive bootloader console. Logs all RX bytes and every TX
action with millisecond timestamps.

Usage:
    python scripts/uart_tx_probe.py --out-dir <path> [--port COM3] [--cycles N]

Output contains device identifiers. Keep the log outside the repository;
run redact_uart_log.py on a copy before sharing.
"""
import sys
import argparse
import time
# Force UTF-8 stdout on Windows to avoid cp1252 encoding errors
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from datetime import datetime
from pathlib import Path


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def is_ascii_chunk(data: bytes, threshold: float = 0.75) -> bool:
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= threshold if data else False


# Sequences to send during LK ASCII phase, in order
LK_PROBES = [
    (b"\r",                  "Enter"),
    (b" ",                   "Space"),
    (b"\x03",                "Ctrl-C"),
    (b"\r",                  "Enter"),
    (b"help\r",              "help"),
    (b"?\r",                 "?"),
    (b"\r",                  "Enter"),
    (b"reboot-fastboot\r",   "reboot-fastboot"),
    (b"download\r",          "download"),
    (b"fastboot\r",          "fastboot"),
    (b"boot\r",              "boot"),
    (b"\r",                  "Enter"),
    (b"\x03",                "Ctrl-C"),
    (b"\r",                  "Enter"),
]

# Send these during the first 500ms of the preloader binary phase
PRELOADER_PROBES = [b"\r", b" ", b"\r"]

KERNEL_MARKERS = (b"Linux version", b"Booting Linux", b"Starting kernel")
LK_ASCII_TRIGGER = 30   # bytes of printable ASCII before probing starts


def run_probe_loop(port: str, baud: int, out_dir: Path, max_cycles: int):
    import serial

    cycle = 0
    print(f"[{ts()}] uart_tx_probe starting: {port} @ {baud}, output -> {out_dir}")

    while max_cycles == 0 or cycle < max_cycles:
        cycle += 1
        log_path = out_dir / f"uart_probe_{datetime.now():%Y%m%d_%H%M%S}_c{cycle:04d}.txt"

        ser = serial.Serial()
        ser.port = port
        ser.baudrate = baud
        ser.timeout = 0.05
        try:
            ser.open()
        except serial.SerialException as e:
            ser.close()  # ensure handle released even on partial open
            print(f"[{ts()}] Cannot open {port}: {e}  (retrying in 3s)")
            time.sleep(3)
            cycle -= 1
            continue

        with open(log_path, "w", encoding="ascii", errors="replace") as log:
            def w(msg: str):
                line = f"[{ts()}] {msg}"
                print(line, flush=True)
                log.write(line + "\n")
                log.flush()

            w(f"=== CYCLE {cycle} START  log={log_path.name} ===")

            phase = "idle"          # idle | preloader | lk | kernel
            ascii_run = 0
            lk_probed = False
            preloader_probed = False
            boot_start = None
            cycle_start = time.time()
            idle_deadline = cycle_start + 120  # wait up to 2 min for boot

            while True:
                data = ser.read(512)
                now = time.time()

                if not data:
                    if phase == "kernel" and now - boot_start > 35:
                        w("Kernel up, ending cycle.")
                        break
                    if phase == "idle" and now > idle_deadline:
                        w("No boot detected within 2 min, ending cycle.")
                        break
                    continue

                if boot_start is None:
                    boot_start = now

                ascii_dominant = is_ascii_chunk(data)

                # --- Phase transitions ---
                if ascii_dominant:
                    ascii_run += len(data)
                    if phase in ("idle", "preloader"):
                        phase = "lk"
                        w("--- LK PHASE DETECTED ---")

                    # Log LK/kernel text inline
                    log.write(data.decode("ascii", errors="replace"))
                    log.flush()

                    # Detect kernel
                    if any(m in data for m in KERNEL_MARKERS):
                        if phase != "kernel":
                            phase = "kernel"
                            w("--- KERNEL PHASE ---")

                    # Probe LK once we have enough ASCII context
                    if phase == "lk" and ascii_run >= LK_ASCII_TRIGGER and not lk_probed:
                        lk_probed = True
                        w("--- STARTING LK PROBE SEQUENCES ---")
                        for seq, name in LK_PROBES:
                            time.sleep(0.08)
                            ser.write(seq)
                            ser.flush()
                            w(f"TX >> {name}  ({seq.hex()})")
                            time.sleep(0.15)
                            resp = ser.read(512)
                            if resp:
                                printable = resp.decode("ascii", errors="replace")
                                w(f"RX << {repr(printable)}")
                                log.write(printable)
                                log.flush()
                        w("--- LK PROBE SEQUENCES COMPLETE ---")

                else:
                    # Binary phase
                    if phase in ("lk", "kernel"):
                        # Binary after ASCII = new boot starting
                        w("--- NEW BOOT DETECTED (binary after ASCII) ---")
                        ascii_run = 0
                        lk_probed = False
                        preloader_probed = False
                        boot_start = now

                    phase = "preloader"
                    w(f"BINARY [{len(data)}B]: {data[:48].hex()}{'...' if len(data) > 48 else ''}")

                    # Send preloader probes once, ~500ms after first binary
                    if not preloader_probed and boot_start is not None and now - boot_start > 0.4:
                        preloader_probed = True
                        w("--- PRELOADER PROBES ---")
                        for seq in PRELOADER_PROBES:
                            ser.write(seq)
                            ser.flush()
                            w(f"TX >> {seq.hex()}")
                            time.sleep(0.08)
                        resp = ser.read(512)
                        if resp:
                            w(f"RX << {resp[:64].hex()}")

            w(f"=== CYCLE {cycle} END (final phase: {phase}) ===")

        ser.close()
        print(f"[{ts()}] Cycle {cycle} log: {log_path}")

    print(f"[{ts()}] uart_tx_probe finished after {cycle} cycles.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", default="COM3")
    p.add_argument("--baud", type=int, default=921600)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--cycles", type=int, default=0, help="0 = run forever")
    args = p.parse_args(argv)

    if not args.out_dir.is_dir():
        p.error(f"not a directory: {args.out_dir}")

    run_probe_loop(args.port, args.baud, args.out_dir, args.cycles)
    return 0


if __name__ == "__main__":
    sys.exit(main())

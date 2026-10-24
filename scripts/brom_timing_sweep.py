#!/usr/bin/env python3
"""
BROM timing sweep - power-cycle the Crumpet spare unit and watch for
0e8d:0003 (BootROM USB) vs the usual 0e8d:2000 (Preloader USB).

Orchestrates from Windows:
  1. Ensures usbwatch.py is running on the Pi (background).
  2. Loops: Tasmota OFF -> wait -> Tasmota ON -> wait -> parse usbwatch log.
  3. Per cycle, also starts mtkclient on the Pi with --ptype kamakiri and
     --ptype kamakiri2 to attempt crash-to-BROM via the Preloader path.
  4. Prints a summary after every cycle, and a final tally at exit.

Usage:
    python scripts/brom_timing_sweep.py --cycles 50 [--off-time 5] [--on-wait 20]
"""
import sys
import io
# Force UTF-8 stdout so non-ASCII in log messages doesn't crash on Windows cp1252
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import argparse
import subprocess
import time
import json
import re
from datetime import datetime
from pathlib import Path


PI_HOST   = "pi@192.168.1.189"
PI_PASS   = "raspberry"
TASMOTA   = "http://192.168.1.22"
PLINK     = r"C:\Program Files\PuTTY\plink.exe"
PSCP      = r"C:\Program Files\PuTTY\pscp.exe"

BROM_VID_PID  = "0e8d:0003"
PRELOADER_PID = "0e8d:2000"

USBWATCH_REMOTE = "/home/pi/usbwatch_brom"   # remote output dir
USBWATCH_LOG    = f"{USBWATCH_REMOTE}/events.log"


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str):
    print(f"[{ts()}] {msg}", flush=True)


def plink(*args, timeout=30):
    cmd = [PLINK, "-batch", "-pw", PI_PASS, PI_HOST] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        log(f"plink timeout after {timeout}s: {str(e)[:80]}")
        return -1, "", "timeout"


def tasmota(cmnd: str):
    import urllib.request
    url = f"{TASMOTA}/cm?cmnd={cmnd}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log(f"Tasmota error ({cmnd}): {e}")
        return None


def ensure_usbwatch_running():
    """Start usbwatch.py on Pi in background if not already running."""
    rc, out, _ = plink("pgrep -f usbwatch.py", timeout=10)
    if rc == 0 and out.strip():
        log(f"usbwatch.py already running (pids: {out.strip()})")
        return
    log("Starting usbwatch.py on Pi...")
    # </dev/null detaches stdin; echo $! lets the shell exit so plink returns.
    cmd = (
        f"mkdir -p {USBWATCH_REMOTE} && "
        f"nohup python3 /home/pi/usbwatch.py "
        f"--vid 0e8d --out {USBWATCH_REMOTE} --interval 0.01 "
        f"</dev/null > {USBWATCH_REMOTE}/usbwatch_stdout.log 2>&1 & echo $!"
    )
    rc, out, err = plink(cmd, timeout=15)
    time.sleep(1)
    rc2, out2, _ = plink("pgrep -f usbwatch.py", timeout=10)
    if rc2 == 0 and out2.strip():
        log(f"usbwatch.py started (pid: {out2.strip()})")
    else:
        log(f"WARNING: usbwatch.py may not have started. rc={rc} out={out!r} err={err!r}")


def kill_stray_mtkclient():
    plink("pkill -f 'mtk.py' 2>/dev/null; true", timeout=10)


def fetch_usbwatch_log() -> str:
    rc, out, err = plink(f"cat {USBWATCH_LOG} 2>/dev/null || echo ''", timeout=15)
    return out


def parse_brom_appearances(log_text: str) -> list[dict]:
    """Return list of dicts for any appeared event with 0003 product."""
    results = []
    for line in log_text.splitlines():
        if "appeared" in line and "0e8d:0003" in line:
            results.append({"line": line.strip()})
        elif "appeared" in line and "0e8d:2000" in line:
            results.append({"line": line.strip(), "preloader": True})
    return results


def run_mtkclient_cycle(ptype: str, timeout: int = 18) -> tuple[int, str]:
    """Run mtkclient on Pi with given ptype, return (rc, output)."""
    cmd = (
        f"cd /home/pi/mtkclient && "
        f"source /home/pi/mtk-venv/bin/activate && "
        f"timeout {timeout} python3 mtk.py crash "
        f"--skipwdt --ptype {ptype} 2>&1 | tail -30"
    )
    rc, out, err = plink(cmd, timeout=timeout + 10)
    return rc, out + err


def power_off():
    r = tasmota("Power%20OFF")
    log(f"Tasmota OFF -> {r}")


def power_on():
    r = tasmota("Power%20ON")
    log(f"Tasmota ON  -> {r}")


def power_state() -> str | None:
    r = tasmota("Power")
    if r and "POWER" in r:
        return r["POWER"]
    return None


def sweep(cycles: int, off_time: float, on_wait: float, out_file: Path):
    brom_hits = 0
    preloader_hits = 0
    errors = 0

    ensure_usbwatch_running()

    # Note log line count before we start so we only parse new entries
    rc, out, _ = plink(f"wc -l {USBWATCH_LOG} 2>/dev/null || echo 0", timeout=10)
    try:
        baseline_lines = int(out.strip().split()[0])
    except Exception:
        baseline_lines = 0
    log(f"usbwatch baseline: {baseline_lines} lines")

    with open(out_file, "w") as summary:
        def record(msg):
            line = f"[{ts()}] {msg}"
            print(line, flush=True)
            summary.write(line + "\n")
            summary.flush()

        record(f"=== BROM TIMING SWEEP: {cycles} cycles, off={off_time}s, on_wait={on_wait}s ===")

        for cycle in range(1, cycles + 1):
            record(f"--- CYCLE {cycle}/{cycles} ---")

            kill_stray_mtkclient()
            power_off()
            time.sleep(off_time)

            # Snapshot usbwatch line count before power-on
            rc, out, _ = plink(f"wc -l {USBWATCH_LOG} 2>/dev/null || echo 0", timeout=10)
            try:
                pre_lines = int(out.strip().split()[0])
            except Exception:
                pre_lines = baseline_lines

            # Start mtkclient kamakiri on Pi BEFORE power-on
            # (it will wait for device)
            kill_stray_mtkclient()
            ptype = "kamakiri" if cycle % 2 == 1 else "kamakiri2"
            record(f"Launching mtkclient --ptype {ptype} on Pi (waiting for device)...")
            # Use venv python directly (no 'source') + setsid to fully detach
            mtk_cmd = (
                f"setsid nohup /home/pi/mtk-venv/bin/python3 /home/pi/mtkclient/mtk.py crash "
                f"--skipwdt --ptype {ptype} "
                f"</dev/null > /tmp/mtk_cycle{cycle:04d}.log 2>&1 & echo $!"
            )
            plink(mtk_cmd, timeout=30)
            time.sleep(0.3)

            power_on()
            record(f"Waiting {on_wait}s for boot...")
            time.sleep(on_wait)

            # Fetch new usbwatch events
            rc, log_text, _ = plink(
                f"tail -n +{pre_lines + 1} {USBWATCH_LOG} 2>/dev/null || echo ''",
                timeout=15
            )
            events = parse_brom_appearances(log_text)

            brom_this = sum(1 for e in events if "preloader" not in e)
            pl_this   = sum(1 for e in events if "preloader" in e)
            brom_hits += brom_this
            preloader_hits += pl_this

            # Fetch mtkclient output
            rc2, mtk_out, _ = plink(f"cat /tmp/mtk_cycle{cycle:04d}.log 2>/dev/null | tail -20",
                                    timeout=15)

            if brom_this:
                record(f"*** BROM APPEARED ({brom_this}x) ***")
                for e in events:
                    if "preloader" not in e:
                        record(f"  {e['line']}")
            else:
                record(f"Preloader appearances: {pl_this}  BROM: 0")

            record(f"mtkclient ({ptype}) output:\n{mtk_out.strip()}")
            record(f"Running totals: BROM={brom_hits}  Preloader={preloader_hits}")

        record(f"=== SWEEP COMPLETE: {cycles} cycles ===")
        record(f"BROM (0e8d:0003) appearances: {brom_hits}")
        record(f"Preloader (0e8d:2000) appearances: {preloader_hits}")
        if brom_hits:
            record("!!! BROM WAS REACHED — review log above for cycle details !!!")
        else:
            record("BROM never appeared. Either USB BROM window is sub-10ms, or it is fused off.")

    return brom_hits


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cycles",   type=int,   default=50)
    p.add_argument("--off-time", type=float, default=5.0,
                   help="Seconds to keep device powered off between cycles")
    p.add_argument("--on-wait",  type=float, default=22.0,
                   help="Seconds to wait after power-on before next cycle")
    p.add_argument("--out-dir",  type=Path,  required=True,
                   help="Directory for sweep summary log")
    args = p.parse_args(argv)

    if not args.out_dir.is_dir():
        p.error(f"not a directory: {args.out_dir}")

    out_file = args.out_dir / f"brom_sweep_{datetime.now():%Y%m%d_%H%M%S}.txt"
    log(f"Summary -> {out_file}")

    brom_hits = sweep(args.cycles, args.off_time, args.on_wait, out_file)
    return 0 if brom_hits == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

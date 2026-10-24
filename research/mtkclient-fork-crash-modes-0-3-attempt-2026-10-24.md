# mtkclient fork — all four crash modes against live device, 2026-10-24

This is a follow-up to [mtkclient-dumppreloader-da-send-attempt-2026-10-24.md](mtkclient-dumppreloader-da-send-attempt-2026-10-24.md), which settled that crash mode `--mode 0/1/2` sent the exact same header and the same rejection every time. One thing that file's "Not established" section left open was whether a named exploit type (`--ptype`) or a different crash mechanism would behave differently. This session addresses both, using a personal fork of mtkclient that fixes three specific code bugs, two of which directly affect whether `--ptype` reaches the named exploit's dispatch logic at all.

## Fixes in the fork

The fork is `GrahamKowalski/mtkclient`, branch `fix/crasher-mode3-and-run-dump-preloader`, commit `6d6c1c9`. Three changes relative to upstream:

1. **Crash mode 3 missing.** The loop in `crasher()` iterated `range(0, 3)`, so mode 3 (`reset_to_brom`, which uses register writes rather than DA write primitives) was never tried. Changed to `range(0, 4)`.
2. **`--ptype` dispatch never set an exploit for unrecognised or `None` types.** `PLTools.__init__` had no `else` branch, leaving `self.exploit` unset and causing an `AttributeError` on any subsequent call when `ptype` was anything other than `kamakiri`, `kamakiri2`, `amonet`, or `hashimoto`. The fix adds `else: self.exploit = Exploitation(...)` as a fallback. This is the same dispatch bug reported at upstream issue [#350](https://github.com/bkerler/mtkclient/issues/350). The comment in that issue with Crumpet data is mine.
3. **`run_dump_preloader` for non-Kamakiri paths called the wrong method and returned the wrong type.** It called `self.exploit.dump_brom(filename)` (where `filename` was actually the ptype string, not a path) and returned `True` or `False`. Callers expect `(data, filename)`. The fix calls `self.exploit.dump_preloader()` and returns `(data, rfilename)` or `(None, None)` on failure.

## Setup

Same Raspberry Pi 3 with `dwc_otg.speed=1`, same spare Crumpet unit. The fork replaced the pinned upstream commit `cd25cf9`; same venv, no dependency changes. Command: `mtk.py dumppreloader --skipwdt --ptype carbonara`. Session log captured via nohup on the Pi, USB events captured by `usbwatch.py`.

## What happened (observed)

### Connection and identification

The device connected cleanly in Preloader mode, `0e8d:2000`, Full Speed. Identification completed identically to every prior `--skipwdt` result: HW code `0x8167`, subcode `0x8a00`, HW Ver `0xcb00`, SW Ver `1`, target config `0x0` with all flags false. `--skipwdt` bypassed the watchdog-disable step that caused `USBError(5)` in earlier non-skipwdt runs.

### All four crash modes ran

After identification, `crasher()` iterated all four modes. Each is logged by mtkclient with `Exploitation - Crashing da...` regardless of which exploit class is active — this is an artefact of how Python's double-underscore name mangling works with the `LogBase` metaclass; it does not indicate which class was actually dispatched.

- **Mode 0** (`send_da` address 0, length 0x100): rejected with `DA_INVALID_LENGTH (0x7004)`. Same result as every prior run. Device returned to Preloader.
- **Mode 1** (`read32` address 0, count 0x100): no error printed. Device returned to Preloader. `is_brom` false after re-init; loop continued.
- **Mode 2** (`send_da` ARM code to address 0, then `jump_da(0x0)`): `Error on DA_Send cmd`, then `Jumping to 0x0` printed. Device returned to Preloader.
- **Mode 3** (`reset_to_brom(en=True)`, the newly added mode): sent without error. Device returned to Preloader, not to BootROM. `is_brom` still false after re-init.

None of the four modes produced a BootROM enumeration. After exhausting the loop, `crasher()` returned the `rmtk` handle with the device in Preloader mode.

### Dispatch and error path confirmed

After `crasher()` returned, `mtk_main.py` noted the device was not in BootROM mode (`We couldn't enter preloader.`) and called `plt.run_dump_preloader(ptype)`. With fix 3 in place, this reached `self.exploit.dump_preloader()` for the non-Kamakiri branch. That call returned `None` — `Carbonara.dump_preloader()` is inherited from `Exploitation` and is a no-op stub. The error path then printed `PLTools - Error on dumping preloader` and returned `(None, None)`. Session exited cleanly.

Two things are confirmed by the `PLTools - Error on dumping preloader` line: fix 2 set `self.exploit` correctly (without it, the call would have raised `AttributeError` and exited with a traceback instead), and fix 3 reached the correct branch (the old code returned `True`/`False` without any such error line).

## What this means, and what it does not

All four crash modes ran. None reached BootROM. The dispatch fix works in the sense that the code now runs without crashing and reaches the right error path; it does not unblock anything on this device, because the crash step itself fails before the exploit would matter. `Carbonara.dump_preloader()` is a stub that returns `None`, so even with a correct dispatch, no Carbonara-specific exploit logic executed.

The result on crash mode 3 (`reset_to_brom`) is notable specifically because it is a register-write path rather than a DA write primitive path, which is why mode 0 was rejected. Mode 3 completed without an error response, but the device still came back in Preloader mode. That is a data point about this particular unit's reset behaviour, not a conclusion about what other techniques might do.

## Recovery

Full recovery confirmed: normal boot after the session, `BOOT_TIME`, `sec params sbc_enabled = 1`, `Detect production device: True`, LED ring, kernel console. No flash read or write occurred at any point in this session.

## Not established

- Why mode 3 (`reset_to_brom`) returns the device to Preloader rather than BootROM on this unit.
- Whether there is any crash technique that would produce a BootROM enumeration on this device. None of the four modes in mtkclient's `Exploitation.crash()` achieved it.
- Whether `Carbonara.patchda1_and_upload_da2()` — the main Carbonara method, which operates on an already-booted DA rather than a crashed-to-BROM device — would behave differently under a different flow. It was not invoked here; `dumppreloader`'s flow does not call it.
- Whether any other named exploit type would behave differently through this command path. `plstage` failures were recorded separately in [mtkclient-plstage-carbonara-attempt-2026-10-24.md](mtkclient-plstage-carbonara-attempt-2026-10-24.md) before this fork was written; those failure modes sat below where `--ptype` would matter, and those earlier results used the upstream commit, not this fork.

## Handling

No DA, certificate, or device-specific key material was used or produced. No flash was read or written. Raw session logs and USB capture JSON are not included here.

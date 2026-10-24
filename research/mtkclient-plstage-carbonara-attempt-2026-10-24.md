# mtkclient plstage carbonara attempt, 2026-10-24

Having established that mtkclient's `dumppreloader` command only ever runs one fixed crash technique regardless of `--ptype` (recorded in [mtkclient-dumppreloader-da-send-attempt-2026-10-24.md](mtkclient-dumppreloader-da-send-attempt-2026-10-24.md)), I tried the commands that actually honour `--ptype`: `stage` ("via boot rom mode") and `plstage` ("via preloader mode"). Since this unit has never once enumerated in BootROM mode, only Preloader mode, I used `plstage --ptype carbonara`, reasoning that `carbonara` is understood to be a preloader-mode technique and `kamakiri`/`kamakiri2` are BootROM-mode techniques that would not apply here. I did not try `amonet`: this repo's own independent analysis already documents specific reasons the Amonet Crumpet port cannot work correctly on this device regardless of command, a non-returning code path before it would reach the patched LK, a GPT missing the partition it depends on, and hardcoded patch addresses that land at the wrong place in the actual preloader binary.

## Setup

Same mtkclient install, same pinned commit `cd25cf9`, same Raspberry Pi 3 forcing full speed. `plstage` does not accept `--filename` the way `dumppreloader` does; I found this from the tool's own argument error before anything touched the device, and ran it with just `--skipwdt --ptype carbonara --debugmode` once corrected. Five attempts across two separate sessions caught a connected device.

## What happened (observed)

- Four of five attempts never sent a single byte to the device. Each stayed in mtkclient's "waiting for device" polling state the entire time, logging at most one `Handshake failed, retrying...` line, never progressing further.
- The one attempt that did send anything got partway into a handshake, then settled into a repeating pattern of `Error Accessing String` on several USB descriptor fields and `Input/Output Error`, never reaching the point of printing the device's identification, something `dumppreloader` did within a second or two, every single time I ran it.
- No attempt, across either session, ever produced the clean handshake and device identification that `dumppreloader` and `gettargetconfig` both reliably produced on nearly every try.
- No dump file, no flash read or write, in any attempt.

## What this means, and what it does not

I don't think this result tells us much about `carbonara` as a technique specifically. The failures happened before any payload-type-specific code would run, in `plstage`'s basic device connection, the same command path regardless of which `--ptype` is given. This is the same shape of finding as the `--mode` result on `dumppreloader`: a flag that in principle selects between different things, tested against a problem that sits below where that flag would matter. I'd expect trying `kamakiri2` or another `--ptype` on `plstage` to reproduce the same connection failure rather than reveal something new, though I did not test that directly.

## Recovery (observed)

Every session, across both rounds, left the device able to recover normally. Several boots during these tests showed no stuck-loop symptoms at all, a real difference from `dumppreloader`'s crash attempt, which reliably left the affected boot stalled until a clean power cycle. I confirmed a full clean recovery with a UART capture: normal `BOOT_TIME`, `sec params sbc_enabled = 1`, `Detect production device: True`, LED ring, kernel console reached, `androidboot.verifiedbootstate=green`.

## Not established

- Whether `plstage`'s connection reliability issue is specific to this device, this preloader build, or a more general mtkclient limitation.
- Anything about `kamakiri`, `kamakiri2`, or `amonet` run directly. I did not try them, for the reasons given above.
- Why four of five attempts never exchanged a single byte with the device.

## Handling

No DA, certificate, or device-specific key material was used or produced. No flash was read or written. Raw debug logs and UART logs are not included here, for the same reasons as the earlier capture notes.

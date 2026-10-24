# mtkclient dumppreloader attempt, 2026-10-24

Following the `--skipwdt` follow up in [mtkclient-gettargetconfig-attempt-2026-10-24.md](mtkclient-gettargetconfig-attempt-2026-10-24.md), I tried mtkclient's `dumppreloader` command against the same unit, over the same Raspberry Pi 3 forced full speed connection. This note corrects something from that earlier file, and from an earlier version of this one. I had assumed `dumppreloader` stays at the register read level, the way `gettargetconfig` does. It does not. Since the device is in regular preloader mode rather than BROM, mtkclient's own log shows it automatically falls back to what it labels, in its own words, an exploitation step: `Mtk - We're not in bootrom, trying to crash da...` followed by `Exploitation - Crashing da...`. This is `dumppreloader`'s default behaviour in preloader mode, not something triggered by any flag I passed, confirmed on two separate attempts. I'm recording that plainly, including that I did not expect or intend this specific technique when I proposed trying this command.

Before the results, some context on why this step happened at all. This was one more incremental step on hardware set aside for this kind of testing, following directly from this repo's own [root strategy decision](../docs/crumpet-root-strategy-decision-2026-10-11.md), which asks for new, discriminating, real device evidence before continuing DA level work, rather than more speculative static analysis on its own. The clean, repeatable `--skipwdt` result already recorded is what I'd call that kind of evidence. Every attempt here was logged on both ends, the board's own UART and mtkclient's live session output, and I checked for a full recovery after each session before doing anything further.

## Setup

Same mtkclient install, same pinned commit `cd25cf9`, same Raspberry Pi 3 with `dwc_otg.speed=1` forcing full speed, as described in the earlier notes. Ran as `mtk.py dumppreloader --skipwdt --debugmode --filename <path>`, across three power cycles that caught the device.

## What happened (observed)

1. The handshake, identification, and target config read completed identically to the `--skipwdt` result already recorded: HW code `0x8167`, subcode `0x8a00`, HW Ver `0xcb00`, SW Ver `1`, target config `0x0` with every flag false.
2. mtkclient then sent a one byte command, a 4 byte address (`00000000`), and a 4 byte length (`00000100`, 256 bytes, sent and echoed back twice) as the header for this crash attempt. It did not go on to transmit any payload body. The device read that header and replied with an explicit two byte status code, `7004`, which mtkclient decodes as `DA_INVALID_LENGTH`, rejecting the proposed transfer before any payload bytes were exchanged. This happened on two of the three boots that caught a device.
3. No dump file was ever created on any attempt. Zero bytes were read from or written to the device's flash, and no payload content was ever sent to the device, only the rejected header. I checked this directly, the output file mtkclient would have written simply does not exist.
4. After the DA send was rejected, mtkclient returned to waiting for a device, and the board's own boot stalled the same way recorded in the earlier `--skipwdt` note: no LED ring, no further UART progress past repeated `USB_HANDSHAKE`/`usb receive timeout` lines, on the boots where this happened.

## One boot that did not show the stall

Of three boots, one completed a fully normal boot to kernel console, with the LED ring, `BOOT_TIME: 3867`. I do not think this means `dumppreloader` avoided the problem. That boot shows zero DA related log lines and zero stuck loop lines on either side, which best matches a boot that mtkclient's polling loop simply did not catch in time, the same pattern this project's earlier full speed captures showed before mtkclient was used at all. I'm recording it as an observation, not a success.

## Recovery (observed, confirmed with UART captures)

Disconnecting USB and power cycling after a session like this produces a normal boot, the same baseline as every earlier recovery check in this project: `BOOT_TIME: 1344`, `sec params sbc_enabled = 1`, `Detect production device: True`, LED ring, LK finished, kernel console enabled, zero `USB_HANDSHAKE` or timeout lines. I confirmed this directly from a UART capture of the recovery boot itself, taken right after this specific session.

## How this fits what's already documented here

This repo's existing docs on DA1/DA2 handoff and DA2 Stage 2 failure are built on static disassembly and host side source review, explicitly without a real device trace. This is, as far as I can tell, the first entry in this project with an actual live attempt against real hardware along those lines, and an actual device reported status code in response, rather than silence, a timeout, or a hypothesis. `DA_INVALID_LENGTH` is a specific, named status, not an unexplained short read, and it was returned before any payload content was exchanged. I think that is worth recording precisely, without claiming it explains or resolves this project's broader DA2 questions, which remain open, and without treating a rejected crash attempt as progress toward anything.

## Mode variation follow-up, 2026-10-24

mtkclient's crash technique accepts a `--mode` flag (`0=dasend1, 1=dasend2, 2=daread`). I tried all three against this unit. Every mode sent the exact same header, command `d7`, address `00000000`, length `00000100`, byte for byte identical across default mode, mode 1, and mode 2, and every one was rejected with the same `DA_INVALID_LENGTH (0x7004)` status. No dump file was created in any mode. I confirmed full recovery with a UART capture after each session.

I don't think `--mode` changes anything about this specific crash path on this device. Three independent confirmations of byte for byte identical requests and identical rejections is enough to call this settled, not worth testing further variations of the same technique.

## Not established

- Why the device's chosen length value for this technique was rejected, or what length or technique it would accept, if any. I did not try to find out.
- Whether `DA_INVALID_LENGTH` here is the same underlying cause as this project's existing DA2/XFLASH short read hypotheses, or a separate issue.
- Anything about flash contents. No flash read or write of any kind occurred, and nothing was ever successfully dumped.
- Whether a genuine, signed DA transfer, as opposed to this crash technique, would behave differently. I did not attempt one.
- Whether a different, named exploit payload type (`amonet`, `kamakiri`, `kamakiri2`, `carbonara`) would behave differently through this command path. A fork testing follow-up in [mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md](mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md) ran `dumppreloader --skipwdt --ptype carbonara` with a fixed dispatch and confirmed that the named exploit's `dump_preloader()` method is an uninstrumented stub that returns immediately; the blocker remains the crash step, not the dispatch. The commands that actually honour `--ptype` for a preloader-mode technique in the upstream tool are covered in [mtkclient-plstage-carbonara-attempt-2026-10-24.md](mtkclient-plstage-carbonara-attempt-2026-10-24.md).

## Handling

No DA, certificate, or device-specific key material was used or produced, and none was selected successfully enough to be meaningful even if it had been. The status code and hex values above came from mtkclient's own live session output. Raw debug logs and UART logs are not included here, for the same reasons as the earlier capture notes.

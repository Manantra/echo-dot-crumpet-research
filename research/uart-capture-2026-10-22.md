# UART capture, 2026-10-22

## Capture conditions (observed)

- I did a passive read on one unit (C78MP8). Only the adapter's GND and RX were connected; TX and VCC were left unconnected. The adapter is an FTDI FT232R (DSD TECH SH-U09C5), set to 1.8 V logic. GND went to the gold ring pad under one of the board mounting screws.
- Signal found on pad **TM45** on the bottom (pad) side of the half-disc board `30-004397 REV 01`, at 1.8 V idle (meter: 1.825 V). TM44 read a steady 2.044 V. TM44 was tried at 3.3 V (115200 baud) and again at 1.8 V (115200 and 921600 baud). The two 1.8 V logs hold only 1 and 3 stray NUL bytes after the PuTTY header, with no readable text. The 921600 attempt was logged across a power cycle; for the 115200 attempt that is not recorded.
- I powered the unit by plugging in the supply and pressed no button. The log nonetheless reports `Power key boot` and `power key is pressed` (also `No Battery`).
- I captured with PuTTY 0.85 serial logging at 115200 8N1 and 921600 8N1. The 921600 capture was roughly my third or fourth boot of the unit; I kept only this one capture at each rate. A later 921600 session logged four power-ups in one file: three boots complete and one cut off during the preloader's USB step. The three complete boots matched on build strings (preloader `20231103_072325`), NAND ID, all 18 GPT entries, the security lines, DRAM memory-test result and the LK and preloader boot-time counters. They differed in DRAM training values, `lastpc` values and the `RAM_CONSOLE` signature, which are expected to vary between power-ups. Pad voltages and resistances I measured afterwards are in [hardware.md](../docs/hardware.md).
- The 115200 capture shows readable BootROM output (`F0:`…`Jump to BL`, 11 lines) and then garbage. The 921600 capture is readable from the preloader's first banner (a few bytes of garbage precede it) to `console [ttyMT0] enabled`, about 960 lines.
- Pad function is now **observed on this unit** (UART TX on TM45 at 1.8 V, 921600 after the BootROM). It contradicts the third-party wiki's TM44 = TX / TM45 = RX labelling in [hardware.md](../docs/hardware.md).

## What the log shows (observed)

| Item | Value in this capture |
|---|---|
| Preloader build | `20231103_072325` (also printed as `pl_build_desc=9eb982d-20231103_072325`) |
| LK build | `lk_build_desc=6f7225e-20230407_002912` |
| ATF | BL31 v1.2 (debug), built Jun 26 2025 |
| Kernel | Linux 4.4.22+, debug build banner, built Sep 28 2026 |
| SoC / board | `model=MT8167B`, `compatible=amzn,crumpet-pvt`, `product:crumpet` |
| DRAM | PCDDR3 x16, one rank, 256 MiB at `0x40000000`; memory test passed (16384 passes, 0 fails) |
| NAND | **Toshiba TC58NVG2S0HTA00, ID `98 DC 90 26 76 16`**; 4096-byte page, 256-byte OOB, 0x40000-byte block, 0x20000000 bytes total, 2048 blocks |
| NAND BBT | Tables found at pages 131008 and 130944 (version 1); factory-bad blocks 1536 and 1537 reported |
| GPT | 18 entries (`brhgptpl_0` … `userdata`), parsed identically by preloader (`GPT_PL`) and LK (`GPT_LK`) |
| Active slot | 1 (`boot_b`); boot state green; reason `power_key` |
| Security state | `sbc_enabled = 1`, `prod_dev = 1`, "Detect production device"; LK and TEE verified; anti-rollback fuse and sw version both 1, all checks passed |
| Tool connection | `[BLDR] Tool connection is unlocked`; `[SEC] seccfg part not found`; USB enumeration timed out; `<UART> wait sync time 150ms->5ms`, `received data: ()` |
| LK unlock | `amzn_verify_onetime_unlock_code: Verify one time unlock cert fail, ret = -5` (three times) |
| Kernel console | `console=ttyMT0,921600n1`, `printk.disable_uart=1` |

`check_part_overlapped done` does **not** appear in this capture (searched the whole file).

## Comparison with existing repo claims

| Existing claim | This capture | Status |
|---|---|---|
| Crumpet NAND is Macronix MX30LF4G28AD (`C2 DC 90 A2 57 03`), from the 2019 public log | Toshiba TC58NVG2S0HTA00 (`98 DC 90 26 76 16`) on this unit | **Contradicts for this unit.** Docs that generalise from the 2019 chip need a per-unit caveat. See [hardware.md](../docs/hardware.md), [nand-layout.md](../docs/nand-layout.md), [mtkclient-stage2-nand-profile-transport.md](../docs/mtkclient-stage2-nand-profile-transport.md), [open-questions.md](open-questions.md) item 26. Geometry (4096+256, 2048 blocks) matches. |
| 256 MiB DRAM at `0x40000000` | Same | Independent confirmation, now on a 2023-build unit |
| GPT names, order, LBAs match across 2019 and 2025 | Same 18 entries | Consistent |
| Preloader `20231103_072325` exists on shipped units ([firmware-versions.md](../docs/firmware-versions.md)) | Printed by a live unit | No earlier runtime log of this build in the repo |
| `check_part_overlapped` is printed by 2019 and 2021 preloaders | Absent from this 2023 build's log | Consistent with the absence being a build difference. **Not proof of a fix**; the string may simply not be logged. |

## Not established

- The TC58 datasheet has not been compared against these numbers. Whether OOB layout, ECC strength and scrambling differ from the Macronix assumptions is open.
- Whether other units, especially those matching the 2019 and 2021 logs, use the Macronix part is open.
- The log does not show how the BootROM or preloader responds to a host tool on UART or USB. Only the timeout is visible.
- Nothing here shows DA1 or DA2 behaviour.

USB observations from the same unit, made on 2026-10-23 and 2026-10-24, are in [usb-preloader-capture-2026-10-24.md](usb-preloader-capture-2026-10-24.md).

## Handling

- The raw logs contain hardware identifiers (MEID, hwuid, HRID) and lastpc values. Keep them out of the repo.
- [redact_uart_log.py](../scripts/redact_uart_log.py) now masks those values. It does not mask the `DA_INFO`, `SEC_INFO`, `MD_INFO` and `PART_INFO` words, which may or may not be per-device. Review any redacted log by eye before sharing.

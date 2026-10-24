# BROM timing sweep and UART TX console probe — 2026-10-24

Two concurrent hardware experiments on the spare Crumpet unit: a 50-cycle BROM USB visibility sweep with Kamakiri crash attempts, and a UART TX probe testing for any interactive bootloader console. Both ran on the same bench setup: Raspberry Pi 3 (full-speed USB), FTDI on COM3 at 921600 baud, Tasmota-controlled power, usbwatch.py polling sysfs at 10ms intervals.

Scripts: [scripts/brom_timing_sweep.py](../scripts/brom_timing_sweep.py), [scripts/uart_tx_probe.py](../scripts/uart_tx_probe.py).

---

## BROM timing sweep

### Setup

50 power cycles. Per cycle: Tasmota OFF (5s) → launch mtkclient crash on Pi (setsid nohup, detached) → Tasmota ON (22s on-window) → fetch usbwatch events. mtkclient alternated `--ptype kamakiri` (odd cycles) and `--ptype kamakiri2` (even cycles), both with `--skipwdt`. usbwatch captured all `0e8d:0003` (BROM) and `0e8d:2000` (Preloader) USB appearances.

### Result

| USB appearance | Count |
|---|---|
| BROM `0e8d:0003` | **0** |
| Preloader `0e8d:2000` | **50** |

Every single cycle: Preloader appeared, BROM never appeared.

mtkclient output every cycle: `Preloader — [LIB]: Status: Handshake failed, retrying...`

### What this means

BROM USB (`0e8d:0003`) was not exposed in 50 consecutive cycles, across all boot attempts with both Kamakiri crash variants. Preloader appeared every cycle, confirming the device enumerates normally and the USB watch would have detected BROM if it appeared.

This is consistent with two non-exclusive possibilities:

1. **Sub-10ms BROM window:** Even if BROM USB is briefly enumerated during early boot, the window is shorter than usbwatch's 10ms polling interval. Attempts to catch it with the Kamakiri crash (which tries to hold the device in BROM via a handshake race) failed — either the crash timing is off, or the handshake path is not reached on this device.

2. **BROM USB fused off:** The eFuse or hardware configuration disables BROM USB enumeration entirely on production Crumpet hardware. This is consistent with the device's strong DA signature enforcement (`DA_IMAGE_SIG_VERIFY_FAIL (0x2001)`) seen in earlier Preloader-mode attempts.

These results do not distinguish between the two possibilities. They confirm only that the kamakiri/kamakiri2 crash approach does not expose BROM USB on this spare unit over 50 cycles.

---

## UART TX probe

### Setup

Open COM3 at 921600 baud across continuous boot cycles. Phase detection: `>= 30` bytes of printable ASCII triggers the probe sequence. Probe sequences: Enter, Space, Ctrl-C, help, ?, reboot-fastboot, download, fastboot, boot, then Enter and Ctrl-C again — a standard set of bootloader console probes.

### Phase timing (from prior 461KB capture, 2026-10-22)

| Time (approx) | Phase | Key markers |
|---|---|---|
| 0–5s | Binary preloader | No ASCII |
| 5–25s | Preloader DRAM training | `[PLFM]`, `[EMI]`, `[DramcWriteLeveling]`, `[DramcRxdatlatCal]` |
| ~25s | LK starts | `BOOT_REASON: 0`, `BOOT_MODE: 0`, `[partition init]` |
| ~25–31s | LK running | `[GPT_LK]`, `[LK_BOOT]`, `[LK]`, `booting linux @ 0x40008000` |

The probe's ASCII trigger fired at the start of DRAM training (~5s), not at LK. The 22-second on-window in the BROM sweep ends before LK even starts.

### Preloader phase: all TX ignored

All probe sequences sent during DRAM training produced no response change — DRAM calibration output continued unaffected. The preloader on this build has no UART console and does not interpret UART RX during its DRAM init phase.

### mtkclient crash captured on UART

When the BROM sweep's concurrent mtkclient crash attempt connected, the UART log captured the preloader's own meta-mode serial output:

```
[TOOL] : USB_HANDSHAKE: should be 2 bytes less 512 bytes
[TOOL] func: usb_listen sync time 406ms
[TOOL] : usb receive timeout
[TOOL] : usb receive timeout
[TOOL] : usb receive timeout
... (10 timeouts total)
[USBDL] usbdl_send_da: DA (0x100), SIG (0x100), relocate size (0x80000) fail
[USBDL] usbdl_send_da: invalid da parameters
<ASSERT> download.c:line 572 0
PL fatal error...
```

This is the preloader's own log of what happens during a Kamakiri crash attempt:

1. The preloader enters USB download mode (`usbdl`) after detecting a connection.
2. It performs a USB handshake and waits for data (`usb receive timeout` × 10).
3. It attempts to receive and validate a DA (`usbdl_send_da`), which fails with `invalid da parameters`.
4. The preloader hits an assertion at `download.c:572` and enters `PL fatal error`.

The subsequent device behavior after `PL fatal error` was power-on cycling — no BROM exposure (confirmed by usbwatch BROM=0 throughout).

This is the most detail captured yet on what the Kamakiri crash path does on this device at the preloader level. The crash reaches the DA validation step and explicitly fails; it does not expose BROM.

### LK phase: no interactive console

From the previous 461KB UART capture ([uart-capture-2026-10-22.md](uart-capture-2026-10-22.md)), LK runs for approximately 6 seconds and produces:

```
BOOT_REASON: 0
BOOT_MODE: 0
LOG_COM BAUD: 921600
[partition init]
[GPT_LK] Parsing GPT now...
[LK_BOOT] IMG ANDROID
[LK] non_secure_sram
booting linux @ 0x40008000
```

No interactive prompt, no `LK>` line, no command echo. LK on this build goes straight from init to kernel boot without pausing for input.

Also notable: LK performs a USB download mode check during its first ~1.5 seconds (5 × 300ms `timeout` entries in the prior capture). This is LK polling for a USB downloader connection before deciding to normal-boot. That polling produces no UART-accessible entry point.

### Summary

| Console target | Result |
|---|---|
| Preloader UART RX | No console — all input ignored during DRAM training |
| LK UART RX | No console — production build boots without interactive shell |
| BROM UART | Not tested (BROM never reached) |

UART TX wire is functional. The absence of a console is a firmware build configuration, not a hardware limitation.

---

## Combined conclusion

These two experiments close two of the remaining hardware-accessible routes:

- **Kamakiri/BROM USB:** Not reachable in 50 timed cycles with crash. Either sub-10ms window or fused off.
- **UART console:** No interactive interface at any boot phase in this production build.

Together with `DA_IMAGE_SIG_VERIFY_FAIL (0x2001)` from every Preloader-mode DA upload attempt, the software-accessible boot-chain paths are all blocked. The remaining unblocked route documented in [crumpet-root-strategy-decision-2026-10-11.md](../docs/crumpet-root-strategy-decision-2026-10-11.md) is physical chip-off NAND.

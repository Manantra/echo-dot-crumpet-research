# USB capture of the preloader, 2026-10-23 and 2026-10-24

I connected a USB cable to the USB pads on one unit and watched what the preloader (`20231103_072325`) does, from the UART and from three hosts. This is observation only: nothing was sent to the board, and no tool, handshake or download agent was run.

## Setup (observed)

- A cut USB-A cable. The data wires went to **TM4** and **TM5** on the pad side of the half-disc board `30-004397 REV 01`, first soldered to the pads, later through crimped dupont connectors. Ground went to the gold ring pad under a mounting screw. **VBUS (the red wire) was not connected**, and the Echo ran from its own 12 V supply.
- The cable colours are assumed to be standard (white = D−, green = D+). I only verified that the cable's ground pin was continuous with the ground pad.
- UART output (921600 baud, TM45) was logged with host timestamps, using [uart_timestamp_log.py](../scripts/uart_timestamp_log.py).
- The USB side was watched from a Windows 11 PC (device records and the USB hub analytic event log), a Raspberry Pi 4, and a Raspberry Pi 3 Model B. On the Pi 3, [usbwatch.py](../scripts/usbwatch.py) saved the kernel's cached descriptors without sending any USB traffic.

## 1. Which pad is which (observed, then inferred)

| | A: white on TM4, green on TM5 | B: green on TM4, white on TM5 |
|---|---|---|
| Board UART | `USB High Speed` lines on each bus reset | `USB Full Speed` lines only |
| Raspberry Pi 4 | `Cannot enable` (never gets as far as a speed) | `new low-speed USB device`, descriptor read errors, `Device not responding to setup address`, gives up |

In arrangement A the board completes the high-speed handshake with two different hosts. In B the host classifies the device as low-speed, which is what I would expect if D+ and D− were reversed.

**Inference:** on this unit TM4 is the host-side D− and TM5 is the host-side D+. The no-alexa wiki's "Interfacing" page (third-party reported, device revision not stated) lists them the other way round. Nobody measured the polarity directly; this comes from host behaviour and the assumed cable colours.

## 2. High speed fails on my wiring, full speed works (observed)

| Host and link | Result |
|---|---|
| Windows PC, rear port, soldered joints | In 7.8 s, 36 cycles of: connect, reset, port enabled at high speed, first descriptor request fails with a transaction error, disconnect. No device created. The board logged 36 `USB High Speed` lines. |
| Windows PC, crimped connectors | 17 high-speed enables, 11 disconnects, 17 failed first requests. No device created. |
| Windows PC, through a USB 2.0 hub | No flapping. Four attempts about 0.6 s apart, then "Unknown USB Device (Device Descriptor Request Failed)". |
| Raspberry Pi 4 | `Cannot enable` four times, one port power-cycle, then `unable to enumerate USB device`. |
| **Raspberry Pi 3 Model B, full speed forced** (`dwc_otg.speed=1`) | **Enumerates, in all four of four cycles.** |

I have not established why high speed fails. One candidate is signal quality at 480 Mbit/s over loose, unshielded wires, which is a hypothesis. Capping the link at 12 Mbit/s is what made it work.

## 3. What the preloader presents on USB (observed, full speed, four identical cycles)

- `idVendor=0e8d`, `idProduct=2000`, `bcdDevice=1.00`. Manufacturer `MediaTek`, product `MT65xx Preloader`. **No serial number string.**
- Device: USB 2.00, class `0x02`, 64-byte control endpoint, one configuration. The configuration is marked self-powered, with a maximum power of 500 mA.
- Interface 0 is class `0x0a` (CDC data) with two 64-byte bulk endpoints (`0x01` out, `0x81` in). Interface 1 is class `0x02`, subclass `0x02` (ACM), protocol `0x01`, with CDC functional descriptors and one interrupt endpoint (`0x83`).
- The data interface comes before the control interface. On the Pi, `cdc_acm` fails on interface 0 (`Zero length descriptor references`, error -22) and binds interface 1 as `ttyACM0`. That is my reading of the descriptors.
- The 88 bytes of device and configuration descriptors were identical in all four cycles. SHA-256: `1a445c02f809cf6c0250d4c93a4faf2cbc03c84cd993628b1d34a3906585f313`.

## 4. Timing seen from the UART (observed)

| Situation | `Enumeration(End)` | `BOOT_TIME` |
|---|---|---|
| No cable attached | `TMO 501ms` | about 1344 |
| Host never completes enumeration (Windows, Pi 4) | `TMO 8001ms` | about 8840 |
| Full speed, enumeration succeeds (Pi 3) | `OK`, 347 to 454 ms | 3837 to 3947 |

With a successful enumeration the preloader then logs `usb listen timeout` and `<USB> cannot detect tools!` 2.6 to 2.75 s later, tries UART, and boots LK normally. The device stayed visible on the Pi 3 for 2.665 to 2.675 s in each cycle.

## What I have not established

- **VBUS was never connected.** I don't know whether the preloader behaves differently with VBUS present.
- The cable colours and the polarity inference above, as described.
- This is one unit and one preloader build.
- Both Raspberry Pis reported under-voltage during testing. The results were consistent across cycles, but I can't rule out an effect.
- **Nothing was sent to the board in this note.** A follow-up active test, which did send real commands over this same connection, is recorded separately in [mtkclient-gettargetconfig-attempt-2026-10-24.md](mtkclient-gettargetconfig-attempt-2026-10-24.md).
- Why high speed fails on my wiring.

## Handling

The descriptors contain no serial number. The raw UART logs contain hardware identifiers and are not included, and neither are the packet captures, the Windows event-log exports or the Pi journals.

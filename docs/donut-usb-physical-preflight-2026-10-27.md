# D9N29T / Donut — physical USB preflight and passive host observation (2026-10-27)

**Status: preparation only; the owner-reported D9N29T is still fully assembled, currently powered and connected to Wi-Fi/Internet.** No physical examination, connection, USB session, image acquisition or bootloader modification has yet occurred. This plan does not grant permission for opening, peeling, soldering, probing, rebooting, or exploiting the device. The present Alexa-app release is `13323245700` / `NS6575/8344`; the exact BootROM/preloader behavior on this unit is not yet measured.

**Target distinction:** this is the original 2018 Echo Dot 3 **D9N29T**, `donut_puffin`, eMCP/eMMC. **Never use C78MP8 Crumpet/raw-NAND wiring, Amonet code or images on Donut.**

## 1. An important potentially less invasive access path

Original Donut hardware researcher **Brian Dorey** documents a recessed **six-pad, 3×2, 2-mm-pitch debug cluster** at the bottom of the case, **under the adhesive rubber foot**. In the 2019 [original teardown](https://www.briandorey.com/post/echo-dot-3rd-gen-smart-speaker-teardown) he describes removing that cover and finding the recessed header; the [independent pin measurements and photographed USB adapter](https://www.briandorey.com/post/echo-dot-3rd-gen-digging-deeper) show USB enumeration from an assembled unit fitted with a custom adapter. This **may** avoid complete disassembly for an initial USB investigation, but the foot adhesive may be damaged, the exposed pad geometry/orientation must first be inspected, and a reliable solderless connector has **not** been validated for the owner's device. Both modern installer projects still recommend opening/soldering for a dependable unlock. Do not assume pogo-pin contacts or a hand-held probe are safe during power-on.

**CRITICAL NAME COLLISION:** Dorey's Donut **top microphone/LED board** also carries pads labelled `TM4` (`3.3V`) and `TM5` (`1.8V`) with completely different functions. The USB `TM4/TM5` are on the **base CPU board**, reachable at the bottom cluster. A pad label without its board context is insufficient. Do not use a top-board photo or Crumpet test-point map. Dorey's older photograph of the base board and source page should be used for identification; visual confirmation from the actual target is still required.

### Base-board mapping: source-documented, not yet checked on our unit

| Donut BASE CPU board label | Reference function | USB cable conductor if electrical access is later authorized |
|---|---|---|
| `TM1` or `TM3` | GND | GND (often black; **verify with continuity**, do not trust colors) |
| `TM4` | USB D− | D− (often white) |
| `TM5` | USB D+ | D+ (often green) |
| Other pads in same 3×2 cluster | Includes **12 V and ~1.9 V** according to Dorey's observed hardware | **Never connect or short** |
| External USB 5 V / VBUS | Not used: Donut is powered from its own original supply | **Leave disconnected and individually insulated** |

Read: [Dorey's base-board measurements and USB ID](https://www.briandorey.com/post/echo-dot-3rd-gen-digging-deeper) and [echo-dot-assist pinned Donut wiring notes](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md). Dorey's one-time voltage readings `TM4 0 V` / `TM5 3.49 V` are **not** a universal identification method: voltage depends on operating state and is no substitute for correct board tracing. There is **real short-circuit damage risk** given power pads in the same tiny connector.

## 2. Expected USB mode observations: NOT unlock proofs

| Reference VID:PID | Attribution/evidence | Meaning and limit |
|---|---|---|
| `0e8d:2008` | Original Dorey 2019 Donut readout: MediaTek, `AEODN`, MTP interface | Stock-style USB identity as observed on his unit; not guaranteed to appear on every firmware/state |
| `0e8d:0003` | [TECHO5 Donut hardware documentation](https://github.com/HuskerMinion/techo5-dot/blob/693e9aeb5966d55181e5c660bb0dcbdd5510b60a/docs/hardware-donut.md) | BootROM USB identification on tested board; **neither execution nor unlock is shown by enumeration alone** |
| `0e8d:2000` | Same TECHO5 source | Preloader-side USB enumeration |
| `18d1:4ee2` | Same TECHO5 source | TWRP USB state, which requires the unlock/modified recovery first and must **not** be expected on a locked stock device |

USB IDs can also occur on other MediaTek products and must be combined with already verified model/board identity. The physical interface and boot-mode sequence have not been tested on our unit.

## 3. Phases and stop conditions

### Phase A — now, no touch

1. Record model from case (`D9N29T`) and app firmware (`NS6575/8344`). Save reference screenshots with serial, QR, MAC and account identifiers redacted.
2. Because the stock device currently has Internet access: **do not start a new setup, manual update or factory reset**. Check for active update indications before intentionally cutting power or connectivity. If appropriate, arrange *per-device* WAN blocking in the router once no update is active. A new isolated SSID does not evict a remembered real Wi-Fi network; a firewall cannot guarantee all traffic is absent without testing.
3. Choose a **native Linux** USB host for eventual Kamakiri operations. The project warns that macOS, WSL and VM USB passthrough may lose BootROM timing. Native Linux is not necessary just to photograph the unit.

### Phase B — host-only readiness (may be completed without an Echo)

Do not run any unlock tooling or `udev` installer to do a host readiness check. On the selected Linux host these commands query only its own setup and need no admin privileges:

```sh
uname -srm
for tool in lsusb python3 sha256sum adb fastboot dmesg udevadm; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "%-12s %s\n" "$tool" "$(command -v "$tool")"
  else
    printf "%-12s MISSING\n" "$tool"
  fi
done
lsusb
```

**Interpretation:** a missing tool only means the host needs preparation later, not that the Echo is unsupported. This check does not pair with, enumerate or alter an Echo. Protect host-specific identifiers if sharing output.

### Phase C — physical inspection of under-foot pad cluster (future separate consent)

Unplug the Echo's **external power adapter** and all other cables first. If the owner chooses to risk adhesive/cosmetic damage, peel the rubber foot only as necessary for a photograph of the recessed **base-board** six-pad cluster. Do not unscrew the main case, use powered probes, solder, bridge pads, or connect a USB cable merely to take the photograph. Verify actual footprint and orientation against donor board photos **before** trusting the TM names. A high-quality photograph of the contact pattern and surrounding silkscreen (not serial label/QR) is the checkpoint. If uncertain, stop.

### Phase D — passive USB enumeration (future separate consent, after electrical review)

Only with an *individually confirmed*, mechanically stable, short-free 3-wire USB data connection (D−, D+, ground) plus original Echo supply and **no external USB VBUS**, consider asking Linux what enumerates:

```sh
lsusb -nn -d 0e8d:
```

For an already intentionally entered USB mode, the host can additionally observe kernel events with `dmesg --follow` (system permissions vary). **These commands only observe host USB state**; they do not send Kamakiri exploits, modify bootloaders, dump private storage or guarantee that *normal boot* cannot itself change data or obtain an OTA if WAN remains reachable.

**Never treat `bootrom-step.sh`, `fastboot-step.sh`, `scripts/setup.sh` (without dry-run), a DA upload, `fastboot flash`, a TWRP installer, `adb reboot`, or a factory reset as a harmless read-only test.** BootROM-only enumeration and actually running the Kamakiri unlock are separate operations requiring a new risk/restore decision. Do not invoke any `fastboot getvar` until the device is correctly identified in fastboot mode; raw output may include private serial/unlock tokens.

### Immediate STOP

- Unknown PCB revision, orientation, uncertain ground/D+/D− identification, unreliable pad contact or apparent short
- No independent confirmation that the chosen connection keeps USB 5 V disconnected
- Any connection accidentally involving 12 V / ~1.9 V neighboring pads
- Unexpected update, reset prompt, recovery flash, secure-storage/RPMB modification or unexplained disconnection
- Any proposal to run an exploit merely to collect USB VID:PID
- Any indication of overheating, odor, damaged insulation or power instability

## 4. Decision, limits and next observable milestone

**GO for host-only tool inspection and confirming the recessed bottom port by photograph** after intentional safe handling. **NO-GO for live electrical connection until actual-board identification and short-free stable USB interface are established. NO-GO for exploit execution, fastboot/TWRP writes and firmware downgrade.**

The owner has **one stock, powered, network-connected Donut** (current `NS6575/8344`); we have no same-build unlock proof, independently inspected downloaded `kamakiri-donut-v1.0.0.zip`, or validated unmodified pre-unlock backup. A checked software checksum does not eliminate boot-chain brick risk.

**Next data requested when the owner chooses to act:** (a) what native-Linux machine is available; (b) host-only command outputs above if desired; (c) photograph of the **bottom six-pad cluster**, once safely made visible. No device identifiers or private account tokens. Compare the photo **before any pin contact** and reassess whether a properly engineered, mechanically secure, no-VBUS USB adapter is achievable without full disassembly.

## Source pins

- [Brian Dorey, Echo Dot 3 teardown, 2019](https://www.briandorey.com/post/echo-dot-3rd-gen-smart-speaker-teardown)
- [Brian Dorey, Echo Dot 3 base/top board pin table and debug adapter, 2019](https://www.briandorey.com/post/echo-dot-3rd-gen-digging-deeper)
- [Gamer92000 echo-dot-assist Donut 2018 guide `3062695c`](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md)
- [HuskerMinion TECHO5 Donut hardware guide `693e9aeb`](https://github.com/HuskerMinion/techo5-dot/blob/693e9aeb5966d55181e5c660bb0dcbdd5510b60a/docs/hardware-donut.md)
- [Earlier initial Donut feasibility and backup gates](donut-d9n29t-preflight-2026-10-27.md)

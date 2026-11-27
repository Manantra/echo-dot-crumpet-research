# Donut D9N29T USB harness — build plan (2026-10-27)

> **Separate device and project track. Not Crumpet.** This plan concerns a passive 3-wire USB observation harness for the original 2018 Echo Dot 3 **D9N29T / donut**, MT8516, 4 GB eMMC. Never use this harness design, pinout or any Donut artifact on **C78MP8 / crumpet** (raw NAND), or vice versa.

**Status: plan only. No harness has been built, no device contact, no electrical connection, no exploit execution.** Building bench-side components of this harness requires no Echo access and is the explicit next milestone named by both [preflight documents](donut-d9n29t-preflight-2026-10-27.md): *"reassess whether a properly engineered, mechanically secure, no-VBUS USB adapter is achievable without full disassembly."*

## 1. Purpose and hard constraints

The harness exists for exactly one initial purpose: **passive host-side USB enumeration of the Donut BootROM/Preloader**, per [Phase D](donut-usb-physical-preflight-2026-10-27.md). It is not an unlock tool, dumper, or flash interface.

Non-negotiable design constraints (all source-documented, none yet verified on the owner's unit):

| # | Constraint | Source basis |
|---|---|---|
| C1 | **Exactly three conductors**: GND (`TM1` or `TM3`), USB D− (`TM4`), USB D+ (`TM5`) on the **base CPU board** bottom cluster | Dorey 2019 base-board measurements; cross-checked by two Donut projects |
| C2 | **No VBUS, ever.** The Donut is powered solely by its own 12 V adapter. The USB cable's red 5 V conductor must be **cut at the host connector and individually insulated**, with an open-circuit bench proof before any device contact | Both Donut guides require disconnecting/insulating USB 5 V |
| C3 | **No possibility of contacting the neighboring power pads.** The 3×2, 2-mm-pitch cluster contains **12 V and ~1.9 V** pads. The fixture must physically preclude contact with them (contact mask/spacing guard), not merely rely on careful aiming | Dorey's observed hardware; short-circuit damage risk called out in the physical preflight |
| C4 | **Solderless first.** A pogo/pressure contact fixture is preferred over soldering an assembled board; soldering on the owner's unit remains a separate later decision | Preflight: "a reliable solderless connection ... has not been demonstrated on the owner's unit" |
| C5 | **Pad identity is checkpoint-gated.** No harness may be finalized, matched or attached to the device until the Phase C photograph of the *actual owner unit's* base-board pad cluster exists and matches donor photos. A pad label without the base-board context is insufficient (the top mic/LED board has unrelated `TM4/TM5` pads) | Physical preflight "CRITICAL NAME COLLISION" |
| C6 | **Fail-closed stop conditions apply at every phase**, reusing the preflight's Immediate STOP list (uncertain orientation, unstable contact, any suspected short, unexpected device behavior) | Physical preflight §3 |

## 2. Phase plan

### Phase H0 — documentation and host readiness (no Echo needed, no risk)

1. Confirm the native-Linux host using the already-defined [Phase B host-only checks](donut-usb-physical-preflight-2026-10-27.md) (`uname`, tool inventory, `lsusb`). No unlock tooling, no `udev` installer.
2. Re-read and pin the two primary sources for the adapter design: [Dorey's base-board measurements and USB adapter](https://www.briandorey.com/post/echo-dot-3rd-gen-digging-deeper) and the [echo-dot-assist Donut wiring notes](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md).
3. Record owner decisions in writing: acceptable cosmetic/adhesive damage to the rubber foot, acceptable brick-risk tier (this plan alone does **not** authorize any exploit), and which host machine will be used.

### Phase H1 — harness design and bench build (no Echo contact)

1. **Option analysis**, best-first:
   - **(a) Pogo-pin fixture**: 2-mm-pitch pogo pins in a small 3D-printed or hand-built jig aligned to the three target pads only, with a physical mask over the three non-target pads (C3). Pros: reversible, no disassembly beyond foot peel. Cons: recessed/curved surface geometry unverified until Phase C photo; contact pressure reliability unproven.
   - **(b) Custom 3-conductor USB cable** terminated to a low-profile connector (e.g., a 2-mm-pitch header block glued into a printed spacer keyed to the recess). Same masking requirement.
   - **(c) Full disassembly + soldered header**: deferred. It exceeds the current consent scope and is only revisited if (a)/(b) demonstrably cannot hold stable contact.
2. **Bill of materials (bench side only):** sacrificial USB-A cable; 2-mm-pitch pogo pins or header; multimeter; heat-shrink/individual insulation for the cut VBUS conductor; strain relief; optional printed alignment spacer.
3. **Bench verification checklist — every item must pass before the harness is allowed near the device:**
   - Continuity host-connector↔harness-contact for GND/D−/D+ matches the **expected** mapping; cable colors are never trusted (TM/GND mapping verified by meter, not by wire color).
   - **Open circuit** from host USB pin 1 (VBUS) to every harness contact and to every other pin (C2 proof).
   - No shorts between any two harness contacts.
   - End-to-end functional sanity: the 3-wire cable enumerates a known-good benign USB device? **No — a VBUS-less cable cannot power any device; instead** validate the full cable electrically (step 2/3 checks) and confirm D± continuity with a USB breakout tester that supplies its own power, or accept meter-only validation. Do not improvise external 5 V injection.
4. Photograph the finished harness and the insulation of the cut VBUS conductor for the record (no device identifiers possible at this stage).

### Phase H2 — device-side identity checkpoint (gate; requires the separately consented Phase C photograph)

1. Unplug the Donut's power adapter. Only if the owner accepts adhesive/cosmetic damage: peel the rubber foot just enough to photograph the recessed **base-board** six-pad cluster. No probing, no powered measurements.
2. Compare actual footprint, orientation and silkscreen against Dorey's base-board photo **before** trusting any TM name. If uncertain: STOP, harness stays boxed.
3. Only after the photo matches do we finalize jig dimensions/contact mask against the real geometry. Until then the fixture is provisional.

### Phase H3 — first passive attachment and enumeration (separate consent; read-only)

1. Attach the verified harness with original Echo supply only, **no external USB VBUS** (C2/C3 proofs carried forward).
2. Observe only: `lsusb -nn -d 0e8d:` and optionally `dmesg --follow`. Expected identities and their limits are already tabulated ([`0e8d:0003` BootROM, `0e8d:2000` Preloader, `0e8d:2008` stock MTP, `18d1:4ee2` TWRP-only](donut-usb-physical-preflight-2026-10-27.md)); enumeration alone proves neither execution nor unlock.
3. **Explicitly out of scope for this harness plan**: `bootrom-step.sh`, any DA upload, `fastboot getvar` (leaks serial/unlock tokens), TWRP, downgrade, any partition write. Each is a separate risk/restore decision per the [main preflight gates](donut-d9n29t-preflight-2026-10-27.md).
4. Record timestamps of connect/disconnect and any re-enumeration; sanitize before publishing (no serials, DSN, QR/MAC).

### Phase H4 — evidence write-up and repo integration

1. New dated document `donut-usb-harness-results-<date>.md`, labeled per [CONTRIBUTING](../CONTRIBUTING.md) as **observed** (our bench measurements), **third-party reported** (Dorey/guide values), or **hypothesis**.
2. Update this plan's status header; list any deviation from C1–C6 and why.
3. No firmware images, no unlocked-device artifacts, no private identifiers in the repo.

## 3. Success and stop criteria

**Harness build success (bench-only, H1):** a mechanically stable, short-free, meter-verified 3-wire link with a proven VBUS open circuit and a contact mask that cannot touch non-target pads.

**Operational success (H3):** sustained passive enumeration of a Donut-identified USB device with clean connect/disconnect chronology and zero stop-condition events.

**Immediate STOP (carry-over from the physical preflight, plus harness-specific):** uncertain pad identity or orientation; unstable or intermittent contact; any measured continuity suggesting a short; any sign the fixture could shift onto a power pad; unexpected device update/reset behavior; overheating or damaged insulation; any proposal to advance beyond passive enumeration using this harness as justification.

**Failure disposition:** if pogo/pressure contact proves unreliable after the Phase H2 photo, do not escalate to soldering by default — that is a new consent decision with its own brick-risk assessment, not a debugging step.

## 4. Source pins

- [Brian Dorey, Echo Dot 3 base-board pin table and debug adapter, 2019](https://www.briandorey.com/post/echo-dot-3rd-gen-digging-deeper)
- [Brian Dorey, Echo Dot 3 teardown, 2019](https://www.briandorey.com/post/echo-dot-3rd-gen-smart-speaker-teardown)
- [Gamer92000 echo-dot-assist Donut guide `3062695c`](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md)
- [HuskerMinion TECHO5 Donut hardware guide `693e9aeb`](https://github.com/HuskerMinion/techo5-dot/blob/693e9aeb5966d55181e5c660bb0dcbdd5510b60a/docs/hardware-donut.md)
- Prior gates: [Donut bootloader preflight](donut-d9n29t-preflight-2026-10-27.md) and [physical USB preflight](donut-usb-physical-preflight-2026-10-27.md)

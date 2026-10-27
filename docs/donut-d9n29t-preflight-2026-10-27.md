# Donut D9N29T: bootloader-unlock and recovery preflight (2026-10-27)

> **Separate device and project track. Not Crumpet.** This document covers the original 2018 Echo Dot 3 **D9N29T / donut / donut_puffin**, **4 GB eMMC**, not Echo Dot 3 Refresh **C78MP8 / crumpet / raw NAND**. Never interchange flash images, unlock kits, device pinouts or restoration claims.

**Owned device's user-reported state:** `D9N29T`, Alexa-app software version `13323245700`, corresponding to public **Fire OS 6.5.7.5 / NS6575/8344**, recorded 2026-10-21. The app version is not a direct preloader/BootROM measurement. This is distinct from the user's Crumpet on `13222532484`.

**Scope:** primary-source read-only review of public project instructions, actual shell/Python installer source and vendor OTA catalog metadata; no actual Echo, USB, bootrom, electrical contacts, code execution, flashing or firmware modification. The **firmware ZIPs and unlock attachments were not locally obtained and independently SHA-256 checked**. Do **not** interpret their published hash lists as having been recomputed here. The XDA attachment itself has not been independently source-audited; its documentation is cited through the two projects that use it.

**Pinned source versions checked:**
- [Gamer92000/echo-dot-assist `3062695c586b03371ee63a0c63376f6c214721ef`](https://github.com/Gamer92000/echo-dot-assist/tree/3062695c586b03371ee63a0c63376f6c214721ef)
- [HuskerMinion/techo5-dot `693e9aeb5966d55181e5c660bb0dcbdd5510b60a`](https://github.com/HuskerMinion/techo5-dot/tree/693e9aeb5966d55181e5c660bb0dcbdd5510b60a)
- [FTVDB Donut firmware index](https://ftvdb.com/echo/firmware/com.amazon.donut.android.os/).

## 1. What is known, and what is *not* proven for the user's firmware

| Gate | Present evidence | Decision |
|---|---|---|
| Device identity | Physical label reported `D9N29T`; Donut is explicitly supported by both projects. Fire OS number `13323245700` is a known Donut vendor catalog entry, but these numeric codes are also used by other Echo models. | Model family **yes**, exact boot-chain compatibility **unverified** |
| Original unlock | Both projects cite the `kamakiri-donut-v1.0.0.zip` kit from [XDA](https://xdaforums.com/t/unlock-root-twrp-unbrick-amazon-echo-dot-3rd-gen-2018-donut.4801400/), described as BootROM exploit followed by patched fastboot/TWRP. Real-device Donut successes are reported. | **Existing Donut route**, not an attested same-build `NS6575/8344` run |
| Fire OS compatibility | `echo-dot-assist` pins **`NS65741/8138`** (build `13222529668`, Aug 31 2026). Its device configuration sets `FIRMWARE_ID=NS65741`; its setup rejects wrong firmware-file checksum, and its `probe.sh` compares selected device binaries against that build once root adb exists. | Current `NS6575/8344` is **not install-ready** |
| Reverting to `NS65741/8138` | The described workflow flashes the older vendor OTA into both A/B slots **through TWRP after unlock**; it is **not** a non-invasive over-the-air downgrade. TWRP's A/B switching is explicitly verified by its installer and should not be overridden blindly. | **Destructive; test and restore prerequisites not met** |
| TECHO5 Dot | Supports Donut after `kamakiri-donut` and stock Fire OS `6574.1`; its Linux image replaces TWRP in **`swdl`**, uses the unit's stock kernel and modules. Source-level `install-dot.py` checks for generic `Fire OS 6`, **not** the exact `NS65741/8138` binary version; therefore its broad guard must not be treated as a full firmware compatibility guarantee. | Downstream alternative **after** supported unlock/version; independent rollback planning needed |
| Complete factory-original recoverability | The TECHO5 installer backs up boot-critical partitions after unlocked TWRP/root, MD5-compares each transfer, and stores TWRP's `swdl`. That is good **post-unlock protection**, not a validated pre-exploit complete, untouched eMMC backup nor proof of cold-boot full restoration. The project expressly lists Donut rescue-after-five-failed-boots as **not yet tested** on that board. | **Incomplete** for a zero-risk initial unlock |
| Source kit execution audit | Project docs list checksums and scripts, but no locally downloaded kit was inspected or executed in this audit. | **Open** |

## 2. Published exact file names and expected checksums

These are **developer-published target SHA-256 hashes**, NOT independently recomputed local checksums. Do not rename a different firmware to these filenames or substitute Crumpet firmware.

| Purpose | Exact file | Expected SHA-256 | Provenance |
|---|---|---|---|
| Donut stock Fire OS 6574.1 required by echo-dot-assist | `update-kindle-donut_puffin-NS65741_user_8138_0013222529668.bin` | `ac22b78cf94c2ebacfa90447b770b803d9f72f35858d5218975d97fea95a0245` | [FTVDB record with official Amazon CloudFront archive URL](https://ftvdb.com/echo/firmware/com.amazon.donut.android.os/f7cd5f3b6d6bfa59e5ba6a6779285c34-13222529668-fire-os-6574-1-ns65741-8138-2026-08-31/), and [echo-dot-assist exact checksum list](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md) |
| BootROM unlock + patched fastboot + TWRP | `kamakiri-donut-v1.0.0.zip` | `4d2bb52eaf661f6616aa4268584d44cf9155c1328c34bfcba01a6558f942b738` | [Project instructions](https://github.com/Gamer92000/echo-dot-assist/blob/3062695c586b03371ee63a0c63376f6c214721ef/devices/donut/README.md), original [XDA thread](https://xdaforums.com/t/unlock-root-twrp-unbrick-amazon-echo-dot-3rd-gen-2018-donut.4801400/) |
| Root adb / SELinux patch | `boot-root.zip` | `de49cc88b27a8e77cf97cf0156bee50e4ddc0e116c41aaede06b494e38397be0` | Same project/XDA sources |

The [vendor catalog](https://ftvdb.com/echo/firmware/com.amazon.donut.android.os/) lists the current `NS6575/8344` and the older `NS65741/8138` as **different** published builds. FTVDB provides the 8138 archive's independent metadata MD5 `f7cd5f3b6d6bfa59e5ba6a6779285c34`, **not** an independent verification of the downloader-provided SHA-256 above. Matching a local checksum proves byte identity with the listed artifact, not vendor code-signing validity or anti-rollback compatibility.

**Safe preflight when files are separately, legally acquired to a local computer**: compute local `sha256sum` on each named file and match the full 64 hexadecimal characters above; reject any mismatch before attempting to execute/install anything. Do not publish third-party ZIPs or Amazon binaries in the research repo.

## 3. Actual device hardware and host prerequisites

The [Donut hardware reference](https://github.com/HuskerMinion/techo5-dot/blob/693e9aeb5966d55181e5c660bb0dcbdd5510b60a/docs/hardware-donut.md) documents an MT8516 / 4 GB eMMC device with distinct A/B `system`, `boot`, `lk` partitions and **`swdl` (32 MiB)** where patched recovery boots. This is not Crumpet NAND.

There is no outside USB data jack. Two projects independently document **board USB D− = TM4, D+ = TM5, GND = TM1 or TM3**, and **the USB cable's red 5 V VCC wire must be disconnected and insulated** because the Echo is powered only by its own 12 V adapter. The exact board/pad identification, insulation, continuity and solder quality require physical confirmation **before touching an owned device**. No pin connecting, opening, pad probing or actual command execution is authorized by this preflight.

The original unlock path calls for **native Linux on a PC** rather than macOS/virtualized USB/WSL, with direct USB and `python3`/fastboot/adb; later post-unlock management is less host-specific. A Linux live USB is an option, but **it is not a recovery guarantee**. The developer reports security/reliability limitations and a brick risk.

## 4. Backup boundary – before versus after the exploit

1. **Before touching a stock locked Echo:** The Alexa-app build and physical model are known. There is **no demonstrated supported full raw-eMMC backup in this state** from the cited installers. Do not assume `adb` access or `scripts/probe.sh` on a fully stock locked Echo: that script explicitly states the stock Echo has no adb.
2. **BootROM unlock / patched boot chain:** The kit is an actual modification, not a read-only probe. It is the first high-risk step and precedes TECHO5's partition backup. Successful appearance of TWRP is not evidence of restored factory state.
3. **After unlocked TWRP/root exists:** `techo5-dot/tools/install-dot.py` collects `preloader`, `kb`, `dkb`, `lk_a`, `lk_b`, `tee1`, `tee2`, `expdb`, `misc`, `persist`, `boot_a`, `boot_b`, `swdl`, using the real partition mappings and eMMC boot area and checking copy MD5 against device reads. This is a valuable boot-critical snapshot **after** the boot chain has already been altered. It is not a complete verified before/after full-eMMC restoration drill.
4. **After Linux installation:** `swdl` is repurposed for TECHO5 Linux in place of TWRP. Its project offers a `to-twrp` restoration mechanism, but rescue after five bad boots is expressly **untested on Donut**. Rollback inside a signed TECHO5 update is not equivalent to recovery from a failed initial unlock.
5. **During `echo-dot-assist` install:** the stock `NS65741/8138` OTA is flashed to **both** A/B slots and boot/root/system policies are modified. This wipes user data and can brick the Echo. Preserving the originally installed 6575 firmware would require additional suitable backups and a verified restore route **before those writes**, not merely holding the older OTA archive.

## 5. Go/No-go decision and exact next milestones

**GO: only research/preparation.** Keep the current Donut on the same firmware where possible by preventing ordinary unsolicited Amazon OTA activity once sure no update is in progress (e.g. per-device WAN blocking at router). No need for immediate power cycle. Confirm appropriate host, tools, safe wiring skills and personally acceptable brick risk. Obtain source ZIPs and vendor OTA through their advertised primary sources, and **independently hash the actual downloaded bytes** before reviewing/running any script. Study the original kit's `bootrom-step.sh`, `fastboot-step.sh` and binary/payload hash/provenance first; that was outside this audit.

**NO-GO: any live unlock/downgrade/partition write now.** The exact user's `NS6575/8344` boot chain has not been independently demonstrated with this exploit in this review; the kit's actual bytes have not been audited here; the stock, unmodified system is not fully backed up; and the initial-unlock restore drill is not validated. Opening/soldering and any bootrom command should be a separately understood, explicitly consented physical phase.

**Gate for further progress:** source- and artifact-verified kamakiri kit; same-hardware or relevant-current-build first-hand positive compatibility evidence; known exact safe USB electrical plan; defensible recovery/brick tolerance; and a separate informed decision about unlocking/wiping the donor Donut. **Aim for validated TWRP and read-only identity/boot partition acquisition as the first milestone, not immediate installation of either voice stack.** Different model Crumpet remains out of scope.

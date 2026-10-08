# Unlock / root feasibility review — 2026-10-08

**Device:** Amazon Echo Dot 3rd Gen Refresh, `crumpet` / C78MP8 / Raw NAND.

**Outcome:** No publicly reproducible **working** unlock, persistent root, or tested TWRP procedure was found for stock Crumpet. This is not a statement that all future methods are impossible. Never substitute advice targeting Donut, Biscuit, or Echo Show for Crumpet.

This review combines **first-hand read-only analysis of verified OTA images** with explicitly attributed **community reports**. It does not claim any successful write, downgrade or live-device execution.

## 1. Independent community confirmation, October 2026

In a [Home Assistant thread dated 2026-10-03](https://community.home-assistant.io/t/echo-dot-3rd-gen-2018-as-a-fully-local-assist-satellite-keeping-amazons-mic-array-and-wake-word-engine/1025971/36), researcher JUL14N reports independently reviewing Crumpet firmware and finding known software methods closed on newer units. The author's [echo-dot-assist / echo-dot-codex](https://github.com/adenta/echo-dot-codex) explicitly **does not support `crumpet`**, although it supports older `donut` and other devices.

Treat this as **one researcher's assessment**, not a formal proof that no undiscovered software vulnerability exists.

## 2. Confirmed: newer Preloader resists the published SRAM overwrite

Our [ARM call-chain analysis](tee-header-address-processing.md) shows, in verified 2023-era Preloader builds, the ordinary image-loading path as:

`initial 0x200-byte image-header read → header parsing → optional address transform → numeric text/BSS interval validation → larger image read → separate ATF/TEE verification`.

The new BSS guard protects `[0x00102180,0x00109DAC)`; the upstream attack targets the block-device object at `0x001086EC` and callback at `0x0010870C`, both within that BSS interval. The public `amonet-koboreru` Crumpet port is **untested on hardware**; the author has put raw-NAND variants on hold owing to recovery risk. See [upstream issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2).

**Implication:** The known name-based overlap bypass is not a validated root path on these newer builds. This does not prove all imaginable exploitation paths impossible.

## 3. New first-hand finding: official Amazon LK has an unlock-certificate code path

### Artifact provenance

The **official Amazon May-2025 Crumpet OTA**, indexed by [FTVDB](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json), contains an `lk` partition in its Android `CrAU` payload. We reconstructed that single partition offline via HTTP byte ranges and XZ decompression, and checked *both* its compressed-operation SHA-256 and its uncompressed partition SHA-256 against the OTA manifest:

| Field | Value |
|---|---|
| Manifest partition | `lk` |
| Uncompressed length | **237,568 bytes** |
| SHA-256 | **`c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d`** |
| LK build string | **`20230407_002912`** |

The image has these **ASCII strings**, with file offsets:

| Byte offset | String found |
|---|---|
| `0x2DF84` | `flash:unlock` |
| `0x2DF91` | `flash:otucert` |
| `0x2DF9F` | `flash:otucode` |
| `0x25230` | `amzn_verify_unlock` |
| `0x252DC` | `amzn_set_onetime_unlock_cert` |
| `0x252FC` | `amzn_set_onetime_unlock_code` |
| `0x254F4` | `amzn_verify_onetime_unlock_code` |
| `0x25445` | `%s: Verify one time unlock cert fail, ret = %d` |
| `0x34AC8` | `the command you input is restricted on locked hw` |

These markers **demonstrate code/dispatch names are present**, not that commands are authorized, accepted or safe on a production-locked unit. The flash-prefixed names strongly suggest a vendor certificate/code path for controlled bootloader unlocking, but **we have not reverse-engineered the cryptographic verifier or observed a valid certificate**.

The independent [Crumpet Fastboot research wiki](https://github.com/jvandewiel/no-alexa/wiki/Fastboot) confirms `secure: yes`, `unlock_status: false`, anti-rollback version `0x0001`, reports `amzn_verify_onetime_unlock_code: Verify one time unlock cert fail, ret = -5` and restricted OEM commands. A second independent [hardware/debug project](https://gitlab.com/phodina/echo-debug-gen3) documents the same device family and locked Fastboot variables. Exposed `unlock_code` / `otu_code` fields do **not** mean a user possesses a valid signed unlock certificate.

**Implication:** An Amazon-authorized valid certificate **may** represent a vendor-designed unlock path, but there is **no verified publicly usable route**; do not send arbitrary `flash:unlock`, `flash:otucert` or `flash:otucode` payloads to a production device.

## 4. BROM access is real on some units, but the flash stage is blocked

In [upstream Crumpet issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2), multiple community members report:

- Successful MediaTek **BROM** enumeration on *some* physical units and Kamakiri payload communication.
- The same reported post-BROM failure: DRAM initialization appears to pass, but **DA stage 2 does not execute**, often accompanied by `Stage wasn't executed` / `Failed to upload da`.
- Other devices cannot reach BROM; the accessible USB port may be only the preloader (`0e8d:2000`) or Fastboot (`0bb4:0c01`).
- Three or more reported device dumps share a `20231103_072325` build and SHA-256 `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`.

**Critical distinction:** A successful Kamakiri handshake does *not* equal working NAND read/write, arbitrary payload execution at the needed stage, a persistent bootloader unlock or a recoverable device. Generic `mtkclient seccfg unlock` commands depend on a suitable operational DA path; no such path has been demonstrated here.

The root cause of DA-stage-2 failure has **not** been isolated. Potential classes (hypotheses, not established diagnoses) include incompatibility with the raw-NAND target, an incompatible DA layout or address, DRAM/cache handoff differences and security policy. Need controlled logs and **read-only** analysis before attributing cause.

## 5. New recovery research infrastructure: actual raw-NAND decoding

The [2021 no-alexa hardware study](https://github.com/jvandewiel/no-alexa/wiki/Dumping-NAND-flash) documents **physically reading a desoldered Crumpet NAND chip** with a Raspberry Pi or FT2232H; the resulting dump was scrambled and not directly bootable image data.

The follow-up [2025 wiki explanation](https://github.com/jvandewiel/no-alexa/wiki/Decoding-NAND-flash) now describes the scrambling and error correction. The original author's linked open source [`gilderchuck/mtk-nand-utils`](https://github.com/gilderchuck/mtk-nand-utils) includes:
- `mtk_nand_4k_scrambler.py` — reversible PRBS-15 scrambling/descrambling, 64-page-period masks;
- `mt8167_correct_ecc.py` — BCH ECC correction on 4096-byte data + 256-byte OOB NAND pages; tested on a related MT8516B dump.

This is a **meaningful foundation for offline raw-flash recovery research**, particularly understanding data from physically recovered chips. It is **not** a demonstrated restore procedure: NAND OOB, bad-block tables, boot copy locations, ECC, serial differences and signed/anti-rollback constraints still matter. Even a bit-perfect NAND backup does not alone prove a safely restorable or unlockable device.

Licensing: these utilities have GPL/AGPL licenses; **link only**, do not vendor-copy into our MIT repo without meeting their licenses.

## 6. Which paths are genuinely viable today?

| Candidate | Evidence | Missing requirement | Judgment |
|---|---|---|---|
| Old `amonet-koboreru` crafted TEE on current Crumpet | Public port; static guard resists described overwrite | A known vulnerability and safe NAND write/recovery | **Unproven / high brick risk** |
| Old Preloader downgrade | Historic images available in official OTA | Trusted, recoverable NAND write; signed boot compatibility; anti-rollback | **Unproven / potentially destructive** |
| Fastboot unlock / Amazon one-time cert | Vendor LK functions and strings in verified image | Valid authorized cert / independent proof commands work on production unit | **Interface present, no working public unlock** |
| BROM + Kamakiri + mtkclient | BROM and initial payload reported on some units | Stage-2 DA execution plus raw-NAND and verified recovery | **Partial access only** |
| External NAND dump/readback | Physical chip extraction documented; PRBS + ECC utilities exist | Device-safe reprogramming and full recovery validation | **Read-only research viable; not unlock** |
| JTAG / fault injection | Suggested by an independent researcher | Crumpet-specific reproducible demonstration, hardware and recoverability | **Hypothesis only** |
| Android/userspace vulnerability | No demonstrated stock Crumpet chain | Validated OS code execution, privilege escalation and persistence despite verified boot | **No evidence of working root** |
| TWRP device tree | Source exists | Booting via unlocked LK and raw-NAND-correct storage | **Not an unlock entry** |

## 7. Prioritized non-destructive research plan

1. **High priority — Validate vendor unlock interface offline.** Audit the image's Fastboot command dispatcher and `amzn_verify_onetime_unlock_code` chain for what it requires; distinguish accepted signatures from mere printed `getvar` tokens. No speculative flash commands on locked hardware.
2. **High priority — Understand BROM-to-DA stage 2.** Reconcile the third-party mtkclient failure logs with boot ROM/DRAM/DA assumptions; identify what read-only observations would discriminate between security rejection and incompatible memory initialization.
3. **High priority — Recovery before exploitation.** Map the exact NAND chip revision and board revision, understand OOB/ECC/scrambling and all four redundant `brhgptpl` boot copies, and validate backup integrity with non-invasive or sacrificial hardware before considering writes.
4. **Medium priority — Search for a genuinely new post-2023 loader flaw**, concentrating on proved call-chain conditions; do not assume `amonet` address offsets or known vulnerability names still apply.
5. **Medium priority — Audit kernel/OS images offline**, noting that privilege escalation without a persistent, verified boot chain may only yield temporary root and requires a real test to claim success.

**Success criterion:** A method is only considered **working** once its user-visible steps have been independently reproduced on *real C78MP8 Crumpet hardware* and a post-reboot unlocked or privileged state confirmed, with a documented recovery route. A firmware string, a downloaded OTA, or a synthetic test does **not** meet that criterion.

### Legal / safety scope
Research is intended for hardware you own or are authorized to test. No proprietary firmware is redistributed. **No flash, erase, NAND timing glitches, anti-rollback writes or arbitrary certificate submission has been attempted.**

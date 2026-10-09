# Crumpet C78MP8 root/unlock: evidence-driven feasibility assessment (2026-10-09)

**Device scope:** Echo Dot 3rd Gen **Refresh** / C78MP8 / `crumpet` / MediaTek MT8167 (often MT8516) **raw NAND**. This report explicitly excludes the older `donut` model and the 2nd-generation `biscuit` model.

**Bottom line (as of 2026-10-09): No independently reproduced persistent root, unsigned boot, accepted Amazon unlock certificate or working custom TWRP was found for Crumpet.** The most tangible potential route is **device-specific BROM/Kamakiri → working raw-NAND-compatible RAM-access stage → full recoverable NAND backup → demonstrated old signed Preloader acceptance / another boot-chain bypass → actual Crumpet function mappings → owner-authorized custom boot**. Every arrow past Kamakiri remains open. Do not confuse this research target with a working sequence.

This is read-only archival research. We did **not** connect to a real Echo Dot, use USB commands, execute any exploit, patch a Preloader, flash partitions or generate a modified TEE image.

## 1. What has actually been reached on hardware

In [amonet-koboreru Crumpet issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2), different reporters describe real Crumpet **BROM USB** (`0e8d:0003`), Kamakiri delivery and preloader dumps, with the dumped Preloader SHA-256 `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b` seen on **three reported units**, embedded build `20231103_072325`. Others cannot enter BROM and only see **Preloader USB** (`0e8d:2000`). The reports consistently fail before **Download Agent Stage 2**; `Stage wasn't executed` and `Failed to upload da` recur.

The port's author explicitly says the Crumpet/raw-NAND port is **not tested on real hardware** and is on hold for **high brick risk**, since reliable preloader flashing/restoration is not established. A positive project-roadmap badge pointing at the same code is **not an independent unlock demonstration**.

One reporter describes an *owner-provided physical* BROM observation using a wired D+/D-/GND USB interface and a particular button/power sequence. This is an independent hardware report, **not** a universally safe procedure, electrical design specification or evidence that every board revision enters BROM. Any diagnostic attempt must preserve the original PSU and avoid electrical shorts.

### Evidence levels

| Milestone | Status for Crumpet |
|---|---|
| Signed official OTA files and NAND GPT decoded | **Verified offline**, images from 2019–2025 |
| BROM enumerates on some real devices | **Community hardware reports** |
| Kamakiri sends payload and a Preloader is dumped on some real devices | **Community hardware reports; not reproduced on our own hardware** |
| DA2 runs and reliably reads Crumpet raw NAND | **Not verified** |
| Full 512MiB NAND+OOB with ECC/BBT consistently recovered | **Not verified** |
| Device accepts older Preloader and secure boot still works | **Not verified** |
| Custom signed/unsigned LK, TEE, or Linux boots | **Not verified** |
| Persistent root or accepted vendor unlock credential | **Not verified** |

## 2. Strong newly verified incompatibilities in upstream Amonet Crumpet

Source: [`amonet-koboreru` revision `2a28fd0`](https://github.com/R0rt1z2/amonet-koboreru/tree/2a28fd0). The archived [2019 Crumpet `brhgptpl_0.bin`](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) SHA-256 is `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`. The original Amonet Crumpet header supplies absolute Thumb function pointers with the Thumb bit ORed in. Our [separate ARM bootstrap decoder](crumpet-arm-bootstrap-memory-map.md) validates the GFH image→VMA correspondence.

**Three pinned 2019-data mismatches**, now verified by independent scripts against both original source and original bytes:

| Amonet function pointer | Public 2019 Crumpet image at encoded VMA | Exact evidence |
|---|---|---|
| `PART_GET_ADDR = 0x20F250` | **Second halfword of another 32-bit Thumb-2 instruction** | At `0x20F24E`: `ldr.w r3,[r0,#0x9c]`, bytes `d0 f8 9c 30` |
| `TEE_SET_ENTRY_ADDR = 0x215FE8` | **Inside an ASCII diagnostic string**, not a function body | `[CA Training] Frequency=%d, Rank=%d` |
| `MTEE_VERIFY_DECRYPT_ADDR = 0x21A7EC` | **Inside an ASCII error string**, not a function body | `the MTEE image required external memory size` |

The 2022 and 2025 official Preloaders also place the same fixed `PART_GET_ADDR` into the trailing halfword of other Thumb-2 instructions. The 2021 image has an instruction boundary at that address but not a proven function start.

**This is a major negative compatibility result:** the published fixed Amonet Crumpet function pointers are not validated against **even the available public 2019 Crumpet archival Preloader**. The upstream author may have used an *unexamined different 2019 build or a relocated live RAM image*, so the result does **not** prove no version could work. It does mean the published pointers **must not be applied blindly**.

Additionally, [the original Crumpet `main()` path](amonet-crumpet-unreachable-lk-and-expdb.md) enters a **nonreturning USB-handshake loop**, preceding any custom LK load; the requested `expdb` custom LK destination is **absent** from both CRC-validated 2019 and 2025 raw NAND GPTs; the published wrapper does not include the required stock `tee_crumpet.img` donor. These are **independent source/design blockers**, even *assuming* successful initial exploit entry.

**Read-only regressions added:**
- [2019 TEE pointers vs actual NUL-terminated text](../scripts/audit_2019_amonet_string_pointer_collisions.py)
- [All four pinned archived/official `part_get` Thumb-2 boundary checks](../scripts/audit_crumpet_amonet_part_get_entry.py)

## 3. Do the 2019/2021/2025 security headers suggest an older signed Preloader might boot?

We extracted and inspected six concatenated MediaTek `GFH` records from (a) the public 2019 NAND image and (b) verified official Amazon **2021** and **Nov 2025** OTA `brhgptpl_0` components. Each official component's compressed-operation SHA-256 and final uncompressed SHA-256 matched the containing `CrAU` OTA manifest; the Amazon outer signing certificate itself was **not** separately checked.

All three use the same header sequence:

```text
FILE_INFO (56 bytes)
BL_INFO (12)
BROM_CFG (100)
ANTI_CLONE (20)
BROM_SEC_CFG (48)
BL_SEC_KEY (532)
total GFH chain = 0x300 bytes
```

**Exact finding:** The **BL_INFO, BROM_CFG, ANTI_CLONE, BROM_SEC_CFG and BL_SEC_KEY records are byte-identical across all three images**. The `FILE_INFO` records differ in their declared total file lengths only in this direct byte comparison. All three declare:

- `file_ver = 1`, `file_type = 1`, `flash_dev = 5`.
- `sig_type = 3` (MediaTek-format numeric field; **we have NOT proven its exact cryptographic algorithm**).
- `sig_len = 292` bytes, `jump_offset = 0x300`, `load_addr = 0x00200D00`.
- `max_size = 262,144` bytes; identical attributes `0xC2600001`.

The public 2019 header declares image length **149,576** bytes; official 2021 **149,648**; official 2025 **150,148**.

**Interpretation:** The static security metadata indicates an unchanged header structure and security-config record set, **not** proof that an older Amazon-signed binary would pass the BootROM's signature, eFuse antirollback or device-specific key checks. The active device's reported secure-state/rollback version, the signature's validity and the accept/reject policy must be independently validated *without risking the sole boot copy*.

In fact, the upstream Amonet README uses `check_part_overlapped done` as a heuristic for vulnerable old Preloaders, but in our exact checked images the marker is **present in official 2021** and **absent in public 2019 and Nov 2025**. It is **not a chronological version oracle** and its absence cannot be used to conclude that a 2019 image is patched or safe.

New [read-only GFH signature/security-record comparator](../scripts/audit_crumpet_preloader_gfh_security.py) tests *only pinned images* and disclaims rollback inference.

## 4. A possible non-destructive access path versus a recoverable persistent-root path

**Research candidate A — temporary access:** Try to document the existing community **BROM/Kamakiri Preloader-read primitive**, without writing storage. The next real engineering goal is to determine why Crumpet **DA Stage 2** does not execute: pair exact Stage-1/Stage-2 DA hashes, host patch state, startup memory/EMI and USB status; account for [host-side unchecked Stage-1 setup failures](da1-da2-pairing-handoff-checks.md). Even a valid BROM mode is **not** root.

**Candidate B — older signed Preloader (higher brick risk, not currently actionable):** Only once a genuine low-level backup and independent recovery method exist, determine whether any *already signed* older Crumpet Preloader (for example 2021) actually passes on a given unit and whether its TEE path is vulnerable. This cannot be asserted from `GFH` metadata, superficial string checks or cross-flashing. Do **not** write boot copies, TEE, LK or fuses based on this hypothesis.

**Candidate C — documented Amazon vendor fastboot unlock:** The [actual 2024/2025 LK vendor code](lk-fastboot-unlock-disassembly.md) dispatches `flash:unlock`, `flash:otucert` and `flash:otucode` into certificate/code validators. No accepted vendor-issued unlock credential or bypass has been found. **The presence of the command name is not a working unlock command**. Blind flashing or guessing a certificate is not a safe diagnostic step.

**Candidate D — userland root:** Would require an independently reproducible initial local code-execution entry into Fire OS plus a verified applicable kernel privilege escalation. No known Crumpet-specific public, tested path was identified. Examples of rooting `donut` and `biscuit`, or a generic TWRP build target, do not establish this.

**Our prioritization:** Candidate A (read-only BROM evidence) → safe raw-NAND backup/recovery research → validate code-execution/boot compatibility on the exact target firmware. Candidate B is **not** a user procedure yet.

## 5. Concrete raw NAND recovery geometry and why it matters

A [public older Crumpet UART log](https://github.com/jvandewiel/no-alexa/wiki/UART-logs) identifies the NAND **Macronix MX30LF4G28AD**, device ID `C2 DC 90 A2 57 03`, with a bad-block table recovered from **page 131008** and **page 130944** on that unit. The [manufacturer's MX30LF4G28AD product datasheet](https://www.macronix.com/Lists/Datasheet/Attachments/8864/MX30LF4G28AD%2C%203V%2C%204Gb%2C%20v1.3.pdf) specifies **4,096-byte main + 256-byte OOB pages**, **64 pages/block**, **2,048 blocks**, **5 NAND address cycles** and 4Gb/512MiB main capacity.

Thus, *only for that chip geometry*, a **fully interleaved, unfiltered main+OOB dump** would have exactly **570,425,344 bytes** (131,072 × 4,352), whereas **data-only** is **536,870,912 bytes**. A dump length matching either number proves **nothing about ECC validity, scrambling, bad blocks, decryption, correct per-device calibration or safe restore**. Modern Crumpet units may have different chips; verify chip ID rather than assuming.

The new [read-only NAND dump geometry checker](../scripts/check_crumpet_raw_nand_dump_size.py) calls **`stat()` only** on an already existing local file, distinguishes the two full sizes, and explicitly refuses to certify a restore. **Never clone `idme_nand`, `persist`, keys or device-unique calibration from another unit.**

## 6. Device-owner first checks that do **not** flash or alter hardware state

These commands are **observational only** and apply when the owner already has a *properly wired, electrically safe data connection*. Crumpet reportedly uses independent **12V power** plus data-only USB (historical owner report), unlike micro-USB-powered `biscuit`. **Do not connect 12V to USB pins, short test points or solder on a powered unit.** No universal button combination is guaranteed; owner reports differ by board.

On a Linux machine that already detects a factory/owner-installed USB interface, one may observe USB enumeration without sending a Download Agent:

```sh
lsusb -d 0e8d:0003   # MTK BROM if present, often briefly
lsusb -d 0e8d:2000   # MTK preloader USB, NOT BROM
lsusb -d 0bb4:0c01   # historically reported Crumpet Fastboot USB
```

If an authorized Crumpet is already in Fastboot and has a usable **data** link, these are **read-only** information commands; their support/response differs by firmware:

```sh
fastboot getvar product
fastboot getvar version-preloader
fastboot getvar secure
```

Redact any serial numbers or hardware identifiers from logs before sharing. **Do not** use `fastboot flash`, `fastboot flashing unlock`, `mtk da seccfg unlock`, `mtk w`, arbitrary testpoint shorts, unsigned DA uploads or any BROM RAM-write experiment on a device without proven recovery. Even a command advertised as a diagnostic can affect a device; review it first.

**Interpretation:** `0e8d:0003` would confirm **BROM enumeration only**, not Kamakiri success, DA Stage-2, unlocked bootloader or Linux root. `0e8d:2000` means the Preloader USB interface, not the ROM exploit. An absence of BROM USB is not proof that all board revisions are unexploitable.

## 7. Newly confirmed 2026-10-09 DA2 NAND-chip record and host USB diagnostics

[Detailed direct DA2 binary and XFLASH transport report](mtkclient-stage2-nand-profile-transport.md) confirms the default `MTK_DA_V5.bin` for MT8167 contains a **real NAND-device table entry** pointing to `MX30LF4G28AD` with the historical Crumpet chip ID `C2 DC 90 A2 57 03`, 4096 main/page and 256 OOB/page. The alternative bundled AllInOne agent has no *exact* matching record. The assertion that the stock V5 DA2 lacks a definition for historical Crumpet NAND is therefore contradicted by source bytes; functional NAND access remains untested.

The upstream Python host `boot_to(timeout=0.5)` parameter is a **sleep before status**, not a USB-read timeout. A missing or truncated **12-byte status header** can throw `struct.error` and create the generic `Stage was't executed. Maybe dram issue ?.` message. The host can only reconnect to Stage-2 USB *after* its initial `boot_to` reports success; re-enumeration on real Crumpet is a **hypothesis**, not an observation. `send_data` also has an unbounded loop on repeated USB write failures. Two read-only checks [DA2 lookup profile](../scripts/audit_da2_crumpet_nand_profile.py) and [XFLASH host-path audit](../scripts/audit_xflash_stage2_transport.py) provide reproducible evidence.

**Consequent next investigation:** differentiate DA2 execution vs USB status transport using pre-existing redacted host logs and USB device-event timing, rather than assuming the NAND device is unknown or flashing a different DA.

## New Crumpet BROM/EMI finding: a genuine 2019 parser mismatch, not missing hardware profile

[Full upstream source and original firmware-data audit](crumpet-emi-2019-layout-and-brom-nand-gap.md) shows that the embedded `MTK_BLOADER_INFO_v28` **400-byte EMI block has identical SHA-256 `c2a394...` in verified public 2019, official 2021 and Nov-2025 Crumpet Preloaders**, contrary to suspicion that donor-era EMI differs. The original MTKClient parser incorrectly produces a **37152-byte `emiver=28` blob** from the FF-padded public 2019 GFH layout, while extracting exactly 400B from 2021/2025. Its automatic missing-EMI BROM branch matches by **eMMC CID** and does not query raw-NAND chip IDs; it can continue into Stage2 lacking suitable DRAM initialization. This is a reproducible host-side defect and diagnostic lead, **not** a fix proven on Crumpet hardware. No DA2 run/root/unlock is demonstrated, and raw-NAND writes remain unsafe without validated recovery.

## New Stage-2 root-research narrowing (2026-10-09): DA1 runtime argument magic

The [complete pinned DA1→DA2 R0/magic/SYNC instruction contract](mt8167-da2-bootstrap-r0-magic-sync.md) shows DA2 receives a live parameter pointer in CPU register `R0`, saves it at `0x40000020`, then copies a DA-specific 88-byte or 64-byte parameter struct into BSS. `bootstrap2` checks magic `0xFE4A4D42`, **deliberately infinite-loops if absent**, and only later notifies the host via a properly framed XFLASH `SYNC`. This is a concrete, previously missing possible Stage-2 timeout mechanism even when DA2 entry code is reached. No actual Crumpet R0/memory/USB trace has confirmed this diagnosis. Do not upload alternative DA2 images or cross-pair the DA binaries based solely on this finding.

## 8. Safe evidence needed to establish a real root/unlock breakthrough

We can now state a precise and falsifiable validation bar instead of generic "root coming soon":

1. Hardware/firmware identity confirmed as **C78MP8 / Crumpet** and the **exact installed Preloader and LK version** recorded without modifying flash; redact serial and device identifiers.
2. An **existing owner-authorized log** demonstrates BROM or another first-stage read primitive on the *same hardware*, including the driver/USB phase and stage transitions.
3. A Crumpet-native, individually version/hash-grounded **DA stage 2 or alternative reliable read-only NAND acquisition** independently validated. An in-memory "payload sent" message alone is not sufficient.
4. Two consistent, complete **raw main+OOB snapshots** and a separate supported recovery technique, checking bad blocks, ECC, scrambling and boot-copy metadata. Do not attempt any signed rollback or NAND write before this.
5. A demonstrated **boot-chain authorization bypass or accepted vendor credential** specific to the exact live version, plus independently verified function entry/ABI and recovery. Only then may persistent custom root/boot be claimed.

As of the research date, steps 3–5 are **not met** for current Crumpet. **No working root was discovered.** The current repo contains no malicious signed firmware, modified TEE, flashing recipe or copyright-controlled binaries.

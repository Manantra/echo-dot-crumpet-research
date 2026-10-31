# Crumpet live 2021 keyed-TEE1 experiment: negative result (2026-10-31)

**Scope:** one sacrificial Echo Dot 3 Refresh (`C78MP8` / Crumpet), taken from
stock Fastboot through a RAM-only rescue, a full read-only main+OOB MTD dump,
an offline 2021-preloader/keyed-TEE1/LK composition, and one authorized
seven-partition write. The first post-write boot hung in the keyed TEE1 second
subimage. No software recovery was available. The unit is not a working
unlock and is not recoverable without hardware NAND access.

**This is a research report, not a flashing procedure.** It intentionally omits
raw firmware images, private device identifiers, keys and write commands.

## Evidence levels

- **Directly observed on hardware:** UART boot trace, USB enumeration,
  partition readback hashes, preloader tool responses, Linux `udev` events.
- **Offline verified:** official 2021 preloader/TEE hashes, per-copy BRLYT
  fields, LK patch/header, keyed-TEE1 composition hash, signature audit.
- **Hypothesis, not proved:** the exact keyed-TEE1 layout/callback mismatch;
  whether the KCOL0/BROM path is disabled by eFuse/BootROM policy or by board
  key routing.

## 1. Baseline and read-only acquisition

The unit reached stock Fastboot with the normal Action-button behavior and was
then booted into a RAM-only rescue with root ADB. A read-only dump covered all
18 exposed MTD partitions:

| Item | Result |
| --- | ---: |
| Main-area bytes | 534,773,760 |
| OOB/spare bytes | 33,423,360 |
| Main+OOB page-interleaved bytes | 568,197,120 |
| OOB read failures | 0 |
| Unexposed raw-NAND gap | 2,097,152 bytes |

The dump is the **MTD-exposed** main area plus OOB, not a controller-level
scrambled/ECC raw chip image. The 2 MiB gap is not represented by an MTD
partition.

## 2. Offline image set

The experiment used the official Amazon 2021 preloader copies, the official
2021 TEE2 fallback, the stock LK plus the four-byte functional-unlock patch,
and a crafted keyed TEE1 composition built from the official 2021 TEE donor and
the keyed-recovery overlay.

The four 2021 preloader copies are not byte-identical: only four BRLYT
location bytes differ. Each partition must use its matching copy.

| Partition | Raw SHA-256 | Padded SHA-256 |
| --- | --- | --- |
| `brhgptpl_0` | `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` | `1c917c94a4a67a68d3068b5fe7d1ddb05cb9fbccfe79fccd9d8dfc83fed9862f` |
| `brhgptpl_1` | `3b7f004526084905d4a05f3cd45efff6e6871aa9e7a8abd21a43d19f7fc56a5d` | `af2f364b04332a98a71311c0e717be62b4db99be7221da2b0a755c942f9175ff` |
| `brhgptpl_2` | `ed242bf5dcce75a43d5411eedec7b1a24cfc12c3ae6d63e3c188689c2e2e89cc` | `a141775b8237228e9ba9af8cc9054be60ff58efeb63a1eda5a73969f959c39d2` |
| `brhgptpl_3` | `063e6e09078b494d3922a86e14ae0aae244ed25a469dca5c3c32d07b261a807c` | `2dbd9f6dcd1c9978149e739b9648f8d8b02e4a172c3b5eab5b71bc73ed555928` |

Other images:

| Image | Size | SHA-256 |
| --- | ---: | --- |
| Custom LK raw | 237,568 | `0cf0ba0489c5ac49d9b8ac105e3fe85a8d546229219652888d7778ddd53f0b2d` |
| Custom LK padded for `reserve0` | 786,432 | `c7210b523c551a49dffe4e7d50c01effadf8082b6a358d4e6b2f88ce15e79831` |
| Official 2021 TEE2 padded for `tee2` | 5,242,880 | `0a3e999030e3f8a697ad6bcf12b7b8970a755ffb8d34db6df32879268512b46c` |
| Keyed TEE1 candidate | 1,143,312 | `d8313a7dacfb494091b79112105259794c225de5ffaacb88655355d4023a19bd` |
| Keyed TEE1 padded for `tee1` | 5,242,880 | `a9c8314ca5fa7a645adba42f5ac5692ed42b1a1e8bc5d7292530b7acbc0321e5` |

The keyed TEE1 is a crafted composition, not a vendor-signed TEE. It preserves
the ATF prefix and the stock MTEE header/signature bytes and relies on the 2021
preloader callback-error path to skip the second subimage verification.

## 3. Authorized write and readback

The seven partitions were erased, written and read back in the planned order:

```text
tee2 -> reserve0 -> brhgptpl_3 -> brhgptpl_2 -> brhgptpl_1 -> brhgptpl_0 -> tee1
```

Every full-partition readback matched the expected SHA-256:

| Partition | Readback SHA-256 |
| --- | --- |
| `tee2` | `0a3e999030e3f8a697ad6bcf12b7b8970a755ffb8d34db6df32879268512b46c` |
| `reserve0` | `c7210b523c551a49dffe4e7d50c01effadf8082b6a358d4e6b2f88ce15e79831` |
| `brhgptpl_3` | `2dbd9f6dcd1c9978149e739b9648f8d8b02e4a172c3b5eab5b71bc73ed555928` |
| `brhgptpl_2` | `a141775b8237228e9ba9af8cc9054be60ff58efeb63a1eda5a73969f959c39d2` |
| `brhgptpl_1` | `af2f364b04332a98a71311c0e717be62b4db99be7221da2b0a755c942f9175ff` |
| `brhgptpl_0` | `1c917c94a4a67a68d3068b5fe7d1ddb05cb9fbccfe79fccd9d8dfc83fed9862f` |
| `tee1` | `a9c8314ca5fa7a645adba42f5ac5692ed42b1a1e8bc5d7292530b7acbc0321e5` |

This rules out a torn NAND write as the immediate cause of the first-boot
failure.

## 4. First-boot failure boundary

The first post-write boot reached the 2021 preloader, parsed GPT, loaded and
authenticated `lk_b`, then loaded TEE1:

```text
[PART] Loading tee1 Partition...
[PART] name : atf
[PART] load "tee1" ... [SUCCESS]
[BLDR_MTEE] verify pkcs#1 pss takes 2 (ms)
[PART] name : lk
[PART] size : 1083396
[PART] magic: 58881688h
[PART] check_part_overlapped done
NAND INFO:nand_bread 245: blknr:0xE0F,  blks:0x108
```

The UART then stopped. No further NAND read, USB enumeration, Fastboot or ADB
appeared. The UART segment is 17,572 bytes, SHA-256
`c4ded2bd0d32ac5e7f3f2b244d16f2fffa350a470d01dcc794294130beb17f5b`.

**Observed:** the official 2021 preloader is accepted and executed by the live
BootROM on this unit. The failure is after the preloader has loaded and
verified the ATF and started the second `lk` subimage. It is not a preloader
acceptance failure.

## 5. Recovery attempts

All software recovery attempts failed:

| Attempt | Result |
| --- | --- |
| Volume Down + Action at cold boot | only `0e8d:2000` preloader VCOM; no `0e8d:0003`, no Fastboot |
| Action/KCOL0 grounded at cold boot | only `0e8d:2000` on macOS and Linux |
| Preloader serial tool handshake | successful, but target config `0x00000000`; `memread=false`, `memwrite=false` |
| `JUMP_BL` (`0xD6`) | command echoed, no status/status2, no Fastboot |
| `JUMP_DA` to loaded LK at `0x41e00000` | address echoed, status `0x2001` (`DA_IMAGE_SIG_VERIFY_FAIL`) |
| USB bulk preloader handshake | no preloader transport |
| Linux `udev` during cold cycles | 36 `0e8d:2000` events, **0** `0e8d:0003` events |
| Linux `usbmon` capture | 250,579 bytes; no BROM descriptor observed |

The Linux `udev` log is SHA-256
`56a8c78eb5c16684b2e1ac5312dd5866abc35ad3d168deaca44cde8053f7a17a`.
The result rules out the macOS USB stack as the reason BROM was missed on this
unit.

The unit was powered off. No NAND write was performed after the seven-partition
flash.

## 6. Interpretation

1. **The 2021 preloader is not the failing stage on this unit.** It ran,
   parsed GPT, authenticated LK, and loaded/verified the TEE1 ATF prefix.
2. **The keyed TEE1 second-subimage path is the current failure boundary.**
   The preloader starts reading the second `lk` subimage and never reaches the
   overlay callback. This is consistent with a layout/offset/callback-transition
   mismatch between the crafted image and the preloader’s physical read path,
   not with a bad NAND write.
3. **The emulator’s block-copy geometry needs reconciliation with the physical
   trace.** The observed read starts at `blknr=0xE0F` with `blks=0x108`; the
   offline composition assumed a block-callback transition at a specific data
   offset. That boundary should be re-derived from the preloader code and the
   actual NAND read sequence before another image is built.
4. **BROM download mode is not reachable on this unit through the tested
   KCOL0/Action path.** The same result on Linux rules out host timing as the
   sole cause. Possible remaining explanations are eFuse/BootROM policy, board
   key routing, or a KCOL0 path that is not sampled by this BootROM revision.
5. **No software recovery remains on this unit.** A NAND programmer/test point
   or a BROM-capable replacement unit is required for further iteration.

## 7. Effect on the existing blocker matrix

This experiment adds one important positive observation and several negative
ones:

- **Positive:** the official 2021 preloader is accepted and executed by the
  live BootROM on this unit.
- **Negative:** the crafted keyed TEE1 does not reach its callback/overlay on
  the physical preloader; the first boot hangs.
- **Negative:** the manual Volume Down + Action chord does not enter USBDL on
  this unit.
- **Negative:** BROM `0e8d:0003` is not observed with Action/KCOL0 grounded,
  including on a Linux host with event-level USB capture.
- **Unchanged:** raw-NAND restore, physical current-TEE compatibility, and a
  flashable/verified keyed-TEE1 execution remain unproven.

## 8. What would be needed next

- Reconcile the physical UART read trace with the 2021 preloader’s TEE loader
  and the keyed-TEE1 image layout.
- Test the corrected image only on a unit with a proven recovery path:
  BROM-capable hardware, a known test point, or chip-off/socket NAND recovery.
- Capture a controller-level raw NAND image and prove a restore before another
  boot-critical write.
- Do not treat this report as evidence of a working unlock, TWRP or safe flash
  procedure.

## 9. Sanitized evidence

The raw NAND images, keyed TEE1 image, device serial and write commands are not
included. The hashes and UART excerpt above are the reproducible evidence
surface. The experiment was performed on one sacrificial C78MP8 unit; results
must not be generalized to other units without independent verification.

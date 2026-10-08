# Crumpet raw-NAND boot container and GPT: decoded and CRC-verified (2019–2025)

**Research date:** 2026-10-08 · **Device:** Amazon Echo Dot 3rd Gen Refresh, Crumpet C78MP8 · **Mode:** read-only historical comparison. **Outcome:** The formerly unknown 2025 raw prefix changes have been **fully attributed to GPT GUIDs and CRC32 checksums**. The four boot-copy layout fields can also be related to actual GPT boot-partition starts. No root, unlock, NAND flash, or recovery procedure has been demonstrated.

## Evidence and provenance

Sources inspected:
- Public 2019 **196,608-byte excerpt** `brhgptpl_0.bin` from [jvandewiel/no-alexa](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin), exact SHA-256 `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`. This is **not** asserted to be an entire recoverable flash partition.
- `brhgptpl_0` from official Amazon Crumpet OTA publications **2021-09-09, 2024-01-09, 2025-05-15, 2025-11-28**, and all **four `brhgptpl_*` copies** from Nov 2025. Official historical URLs are catalogued by [FTVDB](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json).
- Each reconstructed **OTA** component and XZ operation was SHA-256-checked against the **CrAU payload manifest**, without independently authenticating the Amazon OTA publisher's signing certificate.
- Independently useful MediaTek source: [U-Boot `mtk_image.h`](https://android.googlesource.com/platform/external/u-boot/+/refs/tags/aml_tz2_305400300/tools/mtk_image.h), which names the `BOOTLOADER!`/`V006`/`NFIINFO` NAND header, `BRLYT` and `GFH` structures. Public [2019 Crumpet UART logs](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) separately print `[GPT_PL]` entries and `[PART] blksz: 4096B` matching our extracted table.

No proprietary Amazon binary, unique partition GUID, customer secret or hardware identifier is stored here. All new Python code is original, read-only research.

## 1. The exact container byte layout has TWO historical packings

| Byte structure | Public 2019 Crumpet excerpt | Official 2021–2025 Crumpet OTA images |
|---|---:|---:|
| `BOOTLOADER!\0` / `V006` / `NFIINFO\0` | `0x0000`, repeated at `0x0100` | `0x0000`, repeated at `0x0100` |
| `BRLYT` MediaTek BootROM layout header | `0x0C00` | `0x1000` |
| `EFI PART` GPT header | `0x2400` | `0x3000` |
| 32 × 128-byte GPT partition-entry array | `0x3000` | `0x4000` |
| MediaTek `MMM\x01` / `FILE_INFO` GFH image | `0x6000` / `0x6008` | `0x8000` / `0x8008` |

The 2019 offset differences explain why **direct raw file-offset comparisons between a public 2019 dump and a modern OTA are misleading**. The available 2019 excerpt is physically differently packed; the exact reason for the historical offset shift has **not** been established. In particular, do **not** infer a new NAND page geometry from these host file offsets alone.

The NAND `V006` header in both layouts includes `ioif=0x100`, declared NAND `pagesize=0x1000` (4096), `addrcycles=5`. Some OOB/pages-per-block fields are **zero or not self-describing** in this header. These fields are not a safe recipe for reconstructing physical OOB/ECC or bad-block handling.

## 2. Both GPT CRC32 fields are VALID

The embedded GPT header is version `0x00010000`, 92 bytes long. Each observed modern image declares **32 GPT entries × 128 bytes** (4096-byte table), of which **18 have active labels**. We independently computed:

| Source | GPT header CRC32 stored / computed | Partition-array CRC32 stored / computed |
|---|---|---|
| 2019 public excerpt | `0x0D429902` / **match** | `0xA56C03BA` / **match** |
| 2021 OTA | `0x876298CF` / **match** | `0x485898E1` / **match** |
| 2024 OTA | `0x1EBE157E` / **match** | `0xF97AD3E3` / **match** |
| May 2025 OTA | `0xBADFC875` / **match** | `0xC0FB0501` / **match** |
| Nov 2025 OTA | `0x04227B52` / **match** | `0x72620AF3` / **match** |

**Important safety warning:** The container embeds a **nonstandard NAND boot GPT-like layout**. Its fields include `current_lba=1`, `backup_lba=1`, `first_usable_lba=3`, yet its first named `brhgptpl_0` entry begins at LBA `0`. This overlaps ranges a general-purpose PC GPT utility would ordinarily reserve. A CRC-valid embedded table here **must not** be treated as an ordinary PC disk GPT or fed blindly to GPT repair, conversion, or flash tools.

## 3. All 18 named partitions are IDENTICAL between 2019 and Nov 2025

The independently CRC-valid 2019 and modern GPT entry tables have **exactly matching names, order, start and end LBAs**. The 4096-byte logical block size also appears in published Crumpet UART traces. LBA values below are read-only forensic data, *not byte offsets for a writing procedure*:

| GPT index | Name | First LBA | Last LBA |
|---:|---|---:|---:|
| 0 | `brhgptpl_0` | `0x0` | `0x3F` |
| 1 | `reserve0` | `0x40` | `0xFF` |
| 2 | `lk_a` | `0x100` | `0x27F` |
| 3 | `lk_b` | `0x280` | `0x3FF` |
| 4 | `brhgptpl_1` | `0x400` | `0x43F` |
| 5 | `reserve1` | `0x440` | `0x5FF` |
| 6 | `idme_nand` | `0x600` | `0x7FF` |
| 7 | `brhgptpl_2` | `0x800` | `0x83F` |
| 8 | `reserve2` | `0x840` | `0x9FF` |
| 9 | `misc` | `0xA00` | `0xBFF` |
| 10 | `brhgptpl_3` | `0xC00` | `0xC3F` |
| 11 | `reserve3` | `0xC40` | `0xDFF` |
| 12 | `tee1` | `0xE00` | `0x12FF` |
| 13 | `boot_a` | `0x1300` | `0x223F` |
| 14 | `tee2` | `0x2240` | `0x273F` |
| 15 | `boot_b` | `0x2740` | `0x367F` |
| 16 | `persist` | `0x3680` | `0x3E7F` |
| 17 | `userdata` | `0x3E80` | `0x1FDFF` |

**Confirmed:** This is a stable *logical* layout in those archival examples, not an independently verified model for all boards or the physical NAND page+OOB layout. Partitions such as `idme_nand` and `persist` may contain device-specific content. **Never clone them from another unit** based on this table.

## 4. Why 2025's different full Preloader SHA-256 hashes are NOT different code

Using the May-2025 and Nov-2025 official `brhgptpl_0` images, **all 309 changed bytes** were exhaustively classified:

| Verified byte class | Number of changed bytes | File offset(s) |
|---|---:|---|
| GPT header CRC32 | 4 | `0x3010–0x3013` |
| GPT **disk GUID** | 16 | `0x3038–0x3047` |
| GPT partition-entry table CRC32 | 4 | `0x3058–0x305B` |
| 18 × GPT **partition unique GUID** fields | 285 | `0x4010–0x489F`, within each 128-byte entry's 16-byte unique-GUID slot |
| All other bytes, including partition first/last LBAs, names, `BRLYT` and `GFH` payload | **0** | — |

There are `18×16=288` unique-partition-GUID field bytes; three bytes coincidentally had equal values in the two versions, yielding **285 actual differing bytes** in those fields.

The entire `[0x8000,0x2D000)` MediaTek GFH image has common SHA-256:

`4e8a844d65e1e0b48512e93011ff4e1bfe78cf72d17ed66daff5cd70ab9da189`

The GUID and CRC32 findings explain every changed partition byte **without invoking a new signature algorithm, exploit fix, NAND controller change, or different Preloader code**. These GUIDs are *OTA-specific random identifiers*; we did not check why Amazon regenerates them on each release.

## 5. The four copy-dependent `BRLYT` fields now match GPT boot-copy starts exactly

On the independent **Nov-2025** OTA `brhgptpl_0..3` copies, each partition is individually SHA-256 validated against the manifest. The `BRLYT` header contains two *duplicated* 32-bit address/length-related fields. We verified a **deterministic relationship** with the correct GPT partition's `first_lba`:

```text
BRLYT field A = brhgptpl_i.first_lba + 0x8
BRLYT field B = brhgptpl_i.first_lba + 0x108
Both appear twice in BRLYT and match exactly.
```

| Copy | GPT partition first LBA | BRLYT A | BRLYT B |
|---|---:|---:|---:|
| `brhgptpl_0` | `0x000` | `0x008` | `0x108` |
| `brhgptpl_1` | `0x400` | `0x408` | `0x508` |
| `brhgptpl_2` | `0x800` | `0x808` | `0x908` |
| `brhgptpl_3` | `0xC00` | `0xC08` | `0xD08` |

This **explains the four changing raw bytes** previously noted at `0x100D`, `0x1011`, `0x101D` and `0x1021` in the 2025 copy comparison. It is no longer necessary to guess that they encode arbitrary instance IDs. The arithmetic relation is verified; the precise *boot-ROM interpretation and units* still require further ROM-level evidence. We have **not** demonstrated that changing them would safely redirect a boot source.

## 6. Read-only independent reproduction

The new [`audit_nand_boot_gpt.py`](../scripts/audit_nand_boot_gpt.py) parses **both** the public 2019 container layout and the official 2021+ OTA variant, verifies NAND/V006 magic and duplicated header, decodes `BRLYT`, verifies the GPT header and 4096-byte partition-array CRC32, lists only partition labels and LBA bounds, and finds the GPT entry whose first-LBA offsets match each BRLYT.

For two selected official Amazon OTAs, the script also classifies **every byte change** (GUID fields, CRC fields, BRLYT copy offsets, or unrecognized):

```bash
python3 scripts/audit_nand_boot_gpt.py \
  --official-ota 'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin' \
  --compare-ota 'https://d1s31zyz7dcc2d.cloudfront.net/2025/11/28/7dba93cd-a7ab-4ba6-ba00-cfcb859d5a7a/update-kindle-crumpet-NS6571_user_6208_0012584501380.bin'
```

For already available archival 2019 `brhgptpl_0.bin`:

```bash
python3 scripts/audit_nand_boot_gpt.py --image /path/to/archived/2019/brhgptpl_0.bin
```

For the latest `brhgptpl_3`, use the November OTA URL and `--copy 3`; the tool prints `BRLYT values match GPT boot partition: brhgptpl_3`.

```bash
python3 -m unittest discover -s tests -v
```

The tests use manufactured image bytes; no copyrighted firmware is committed or included in test fixtures.

### Limitations / recovery safety

This **is not a NAND flashing or root/unlock recipe**. It does not decode raw physical OOB/ECC, bad-block maps, chip scrambling, rollback counters, signed image checks or unit-specific secrets. It does not demonstrate that an OTA's serialized GPT is bitwise identical to a physical chip's GPT. It does **not** establish that standard GPT writing/recovery utilities would be safe; in fact, several nonstandard GPT fields make that a dangerous assumption. Continue the raw-NAND recovery investigation [here](../research/open-questions.md).

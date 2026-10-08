# Verified Crumpet 2021 OTA inventory and preloader extraction

**Date:** 2026-10-08. **Scope:** offline, read-only reconstruction into RAM/local temporary files; no device interaction or flashing.

## Firmware source and integrity

- Product: `crumpet`, **Fire OS 6.5.4.8**, build `NS6548/3252`, full A/B OTA, published 2021-09-09.
- [Firmware-index entry](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json).
- [Historical Amazon CDN OTA](https://d1s31zyz7dcc2d.cloudfront.net/9706cd977e5ea2ca8a021c3cadb620ce/update-kindle-crumpet-NS6548_user_3252_0005805749380.bin) (download may change).
- Archive size **104,334,070 bytes**.
- Archive MD5 **`51fd9be15b07b0dbba8e432e7800ffbb`** — downloaded file matches the archive index.
- Embedded `payload.bin`: **104,321,174 bytes**, Android `CrAU` major version 2, manifest length **4,887** bytes, metadata signature length **264** bytes, block size **4,096**.
- Payload reports **nine updated partitions**: `system`, `boot`, `lk`, `tee1`, `tee2`, `brhgptpl_3`, `brhgptpl_2`, `brhgptpl_1`, `brhgptpl_0`.
- `payload_properties.txt` and `META-INF/com/android/metadata` both identify the relevant Crumpet build.

The four `brhgptpl_*` entries are **actual OTA payload entries**, not names inferred from UART logs. Their `REPLACE_XZ` operations were decompressed, and **both compressed-operation SHA-256 and final partition SHA-256** matched the values in Google's update-engine manifest format. This validates extraction integrity; it does **not** establish the safety of flashing.

## Verified 2021 preloader partition hashes

Each reconstructed image contains **184,320 bytes**, `BOOTLOADER!`, `FILE_INFO` at offset `0x8008`, platform label `crumpet`, and build stamp **`20210326_040236`**.

| OTA partition | Verified SHA-256 of reconstructed image |
|---|---|
| `brhgptpl_0` | `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` |
| `brhgptpl_1` | `3b7f004526084905d4a05f3cd45efff6e6871aa9e7a8abd21a43d19f7fc56a5d` |
| `brhgptpl_2` | `ed242bf5dcce75a43d5411eedec7b1a24cfc12c3ae6d63e3c188689c2e2e89cc` |
| `brhgptpl_3` | `063e6e09078b494d3922a86e14ae0aae244ed25a469dca5c3c32d07b261a807c` |

Each copy contains the text `check_part_overlapped done` at offset **`0x26DEA`**.

## Four-copy comparison

All four 2021 files share an identical executable/data image **except for four single-byte locations** in the early NAND-header region. Relative to `brhgptpl_0`, the other copies differ only at:

- `0x100D`
- `0x1011`
- `0x101D`
- `0x1021`

The reason for those per-copy header bytes remains to be established. **Do not** substitute one NAND partition copy for another.

## Direct 2019 vs 2021 comparison

- [2019 public NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin): **196,608 bytes**; SHA-256 `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`; build `20190926_190455`; `FILE_INFO` at `0x6008`; overlap diagnostic string **absent in this file**.
- 2021 OTA `brhgptpl_0`: **184,320 bytes**; build `20210326_040236`; `FILE_INFO` at `0x8008`; overlap diagnostic string **present**.

Some unchanged regions exist. For example, bytes `2019[0x6320:0x6C00]` equal `2021[0x8320:0x8C00]` (length `0x8E0`), but **the complete binaries are not byte-identical**. This is not a function-level disassembly.

The hardcoded upstream Crumpet DA-verification patch address `0x00217F2C` maps to text in the 2019 image using several *unverified* header-based mappings; corresponding simple mappings in the 2021 image show instruction-like data. That does not demonstrate executable runtime mapping or exploit compatibility.

**Update:** 2021 preloader material is demonstrably obtainable from the official OTA. We later also obtained OTA preloader images with the **2023 build string** from official 2025 packages. See [verified 2021–2025 timeline](verified-preloader-timeline.md). They are not proved bitwise identical to the separately reported community device dump.

## Reproduction without exporting copyrighted firmware

Download the historical OTA from the linked official source, then run:

```bash
python3 scripts/ota_inventory.py /path/to/update-kindle-crumpet-NS6548_user_3252_0005805749380.bin --verify-bootloaders
python3 -m unittest discover -s tests -v
```

The tool reads partition data into memory, checks both layers of SHA-256, prints build stamps and digests, **does not write extracted images**, and never communicates with a device.

## Caveats

- An OTA contains partitions to *update*, which is different from a full NAND chip dump.
- An image shorter than the partition capacity is not automatically an incomplete image.
- This research makes **no claim** that an older preloader can be flashed, downgraded, installed, recovered or used to unlock a modern Crumpet.
- No Amazon binaries are redistributed in this repository.

See: [Android update-engine protobuf definition](https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto), [upstream Crumpet exploit research](https://github.com/R0rt1z2/amonet-koboreru/issues/2).

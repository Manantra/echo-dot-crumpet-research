# Verified Crumpet preloader release timeline, 2019–2025

**Research date:** 2026-10-08. All operations were performed against public firmware and source artifacts. No real Echo Dot was modified.

We inspected the Android A/B `CrAU` OTA manifests through **HTTP Range requests**, and downloaded only the compressed `brhgptpl_*` components. For every reconstructed image listed as verified below, the compressed-operation SHA-256 **and** the partition SHA-256 matched the manifest.

**Caution:** Matching SHA-256 values from the embedded OTA manifest confirms extraction consistency. We **did not independently authenticate the Amazon signing certificate/whole OTA signature**. Preloader build strings are evidence of compilation dates, *not* dates when a firmware was installed on a device.

## Timeline

| Official OTA release | Preloader build string | `brhgptpl_0` SHA-256 | `check_part_overlapped done` |
|---|---|---|---|
| 2019 public NAND excerpt, not an OTA | `20190926_190455` | `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637` (196,608-byte excerpt) | Absent from this excerpt |
| Sep 2021 / Fire OS 6.5.4.8 | `20210326_040236` | `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` | Present, offset `0x26DEA` |
| Nov 2022 / Fire OS 6.5.5.5 | `20220323_062523` | `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d` | Present, offset `0x26E6D` |
| Jun 2023 / Fire OS 6.5.5.9 | `20220323_062523` | `43b593f12409831d3d444b8296d260d9123c6a2edc39ea49d2d10453fb526cbc` | Present, offset `0x26E6D` |
| Jan 2024 / Fire OS 6.5.6.1 | `20230726_065225` | `5a107fa6ae4bdf73cb89ab754eada4d6db5c249446fa6292e86964cc1400b298` | Absent |
| May 2025 / Fire OS 6.5.6.6 | `20231103_072325` | `7b5600978682929661979138fdf687d13ae5b3a2a1a700f59b3daf3bbb86205b` | Absent |
| Nov 2025 / Fire OS 6.5.7.1 | `20231103_072325` | `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a` | Absent |

**Important discovery:** A preloader with the exact build string **`20231103_072325` is publicly retrievable** from 2025 official Crumpet OTAs. This corrects earlier notes saying no binary for that build was available. The frequently reported community dump SHA-256 **`d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`** does **not** match the complete OTA `brhgptpl_0` image hash; build strings alone do not prove bitwise identity with device dumps.

## Byte-comparison observations

The following comparisons use reconstructed `brhgptpl_0` images of **184,320 bytes** each.

| Pair | Different bytes (total) | Difference in file region `[0x8000:0x2D000]` |
|---|---:|---:|
| Nov 2022 → Jun 2023 | 307 | **0 bytes** — identical region |
| Jun 2023 → Jan 2024 | 134,452 | **134,142 bytes** — substantial rebuild |
| Jan 2024 → May 2025 | 610 | **300 bytes**; only **8** differ in `[0x8000:0x26000]` |
| May 2025 → Nov 2025 | 309 | **0 bytes** — identical region |

The first of these pairs shows that different full-file hashes can reflect changes in NAND/early header bytes while the image region at and after offset `0x8000` remains identical.

The large 2023→2024 change, along with disappearance of the diagnostic string, **narrows the location of a substantial firmware change to between the 2022-03-23 and 2023-07-26 preloader builds**. It does **not** establish that a particular memory corruption weakness was fixed. Code-flow disassembly and comparison of the exact routines remain outstanding.

An additional **direct 2019-vs-2023-build byte comparison** (2019 public excerpt vs May-2025 OTA carrying build `20231103_072325`) found **26 aligned, non-overlapping exact-match spans of at least 256 bytes**, totaling **32,256 matching bytes** across potentially different offsets. Many of these matches are headers or shared static data, so this is not a count of unchanged executable instructions. One shared span of `0x4E0` bytes maps 2019 file offset `0x6460` to the 2023-build file offset `0x8460`. A 2023 function-level disassembly remains to be done.

The 2019 public NAND excerpt uses a different wrapper layout (`FILE_INFO` at `0x6008`) and cannot be directly file-offset-aligned against these 2021–2025 OTA images (`FILE_INFO` at `0x8008`).

## Reproduce the OTA checks without downloading multi-megabyte firmware

The official Amazon CDN supports HTTP byte ranges. The accompanying tool fetches a small prefix (ZIP + CrAU manifest) and the four compressed preloader entries, decompresses them **in memory**, and verifies both manifest hashes:

```bash
python3 scripts/remote_ota_probe.py \
  'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin'
```

For 2021, 2022, 2023, 2024 and late-2025 URLs, see the historical [FTVDB Crumpet firmware index](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json). The CDN may remove old archives at any time.

Additional sources: [Amazon/Crumpet research issue](https://github.com/R0rt1z2/amonet-koboreru/issues/2), [public 2019 Crumpet dump](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin), [Android update-engine manifest schema](https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto).

## Safety and limitations

- **Never flash any extracted image based on this research.** Raw NAND bootloader writes are brick-prone and a viable recovery path has not been demonstrated.
- No evidence here demonstrates a working Crumpet unlock, bypass of anti-rollback, or persistent root.
- This repository does not redistribute Amazon firmware.

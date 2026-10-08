# Research status — 2026-10-08

**No proven persistent unlock, root or TWRP for Crumpet (C78MP8).** This repository is research, not a flash guide.

| Topic | Evidence level | Status |
|---|---|---|
| Raw NAND storage | Documented in 2019 Crumpet logs | Confirmed for logged hardware |
| Preloader 2019: `20190926_190455` | Public NAND excerpt and UART logs | Verified source material |
| Preloader 2021: `20210326_040236` | Original official OTA extracted; per-image SHA-256 verified against payload manifest | **Confirmed binary evidence** |
| Preloader 2023: `20231103_072325` | Real official 2025 OTA images with this build string; hashes verified against payload | **Build verified**; exact reported device-dump hash is different |
| BROM/Kamakiri on some Crumpets | User reports | Reported, not a root method |
| Download Agent stage 2 | User reports | Fails on tested devices |
| Crumpet amonet-koboreru port | Author statement | Not tested on actual device |
| 2019→2021 binary comparison | Both source binaries available | Initial byte-level comparison performed; function-level comparison outstanding |
| 2022→2023-build range checking | ARM Thumb disassembly and PC-relative string xrefs | **Confirmed rewrite:** old `0x20F0C0` vs new `0x20F1A0` plus overlap helper `0x20E3D8` |
| 2019→2023 byte-level comparison | Public 2019 excerpt + official OTA image bearing the 2023 build | Byte spans matched; complete function-level correspondence outstanding |
| Runtime patch-address mapping | `FILE_INFO` load address and ARM entry matched on OTA images | **Stored-file VMA mapping corroborated**, live runtime relocation and exploit patch addresses still unverified |
| TWRP for raw NAND Crumpet | Existing shared device tree | Not demonstrated |

See [verified 2021–2025 preloader timeline](docs/verified-preloader-timeline.md), [verified 2021 OTA analysis](docs/ota-2021-analysis.md) (nine partitions, four preloader images, hashes) and [read-only reproduction script](scripts/ota_inventory.py). Ten synthetic tests pass locally (with optional Capstone installed); all examined OTA preloader partition hashes matched their manifests. See [ARM disassembly findings](docs/arm-range-check-analysis.md).

Do not flash Donut images to Crumpet or modify NAND partitions based on these findings.

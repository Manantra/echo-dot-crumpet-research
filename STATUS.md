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
| 2019→2021 binary comparison | Both source binaries available | **Initial byte-level comparison performed**; function-level work outstanding |
| 2019→2023 byte-level comparison | Public 2019 excerpt + official OTA image bearing the 2023 build | **Performed:** matching exact byte spans identified; runtime-aligned disassembly still outstanding |
| Runtime patch-address mapping | File/image wrappers unresolved | Hypothesis only |
| TWRP for raw NAND Crumpet | Existing shared device tree | Not demonstrated |

See [verified 2021–2025 preloader timeline](docs/verified-preloader-timeline.md), [verified 2021 OTA analysis](docs/ota-2021-analysis.md) (nine partitions, four preloader images, hashes) and [read-only reproduction script](scripts/ota_inventory.py). Three synthetic tests pass; all four OTA preloader checksums passed.

Do not flash Donut images to Crumpet or modify NAND partitions based on these findings.

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
| Exploit SRAM target covered by guard | PC-relative initialized memory boundaries in two official images; upstream payload/config | **Verified:** BSS `[0x00102180,0x00109DAC)` contains BDEV `0x001086EC`; published copy size `0x00108804` intersects it |
| 2023-era TEE header address processing | Thumb calls cross-checked in official 2024/2025 OTA images | **Verified:** header parser `0x20F368`, conditional address helper `0x216130`, memory guard `0x20F1A0` before bulk read; exact `0xFFFFFFFF` behavior remains open |
| ATF/TEE load vs signature order | Direct ARM `BL` call graph from official binaries | **Verified:** image data loaded before respective post-load verification wrapper; new guard inside loader before larger read |
| 2019→2023 byte-level comparison | Public 2019 excerpt + official OTA image bearing the 2023 build | Byte spans matched; complete function-level correspondence outstanding |
| Runtime patch-address mapping | `FILE_INFO` load address and ARM entry matched on OTA images | **Stored-file VMA mapping corroborated**, live runtime relocation and exploit patch addresses still unverified |
| TWRP for raw NAND Crumpet | Existing shared device tree | Not demonstrated |
| Amazon vendor unlock code path in LK | Official OTA LK images from 2021, 2022, 2023, 2024, 2025, all manifest-SHA-256 verified; 2024/2025 LK direct ARM/Thumb call graph | **Generic `flash:` dispatch and certificate-gated `unlock` verifier confirmed; no accepted cert or working production unlock known** |
| Physical raw-NAND recovery research | no-alexa chip readout plus independently published PRBS-15 and BCH decoder | **Decode tooling exists**; writing/restoring and boot verification not demonstrated |
| Crumpet BROM + Kamakiri | Third-party reports in upstream issue #2 | Access on some devices; DA stage 2 fails and no proven partition write/recovery |

**No currently validated Crumpet root/unlock path** as of 2026-10-08; see [research feasibility assessment](docs/root-unlock-feasibility-2026-10-08.md) for independent community confirmation, certified-LK findings, BROM limits and recovery prerequisites.

**New:** [2021–2025 LK image version matrix](docs/lk-image-timeline.md) and [vendor unlock ARM call graph](docs/lk-fastboot-unlock-disassembly.md). The 2024/2025 OTA LK partitions are byte-identical; June-2023 and Jan-2024 LK command-dispatch and verification ranges were byte-identical despite differing build stamps. The [OTA Range probe](scripts/remote_ota_probe.py) now supports `--include-lk`.

See [verified 2021–2025 preloader timeline](docs/verified-preloader-timeline.md), [verified 2021 OTA analysis](docs/ota-2021-analysis.md) (nine partitions, four preloader images, hashes) and [read-only reproduction script](scripts/ota_inventory.py). Twenty-six synthetic tests pass locally (with optional Capstone installed); all examined OTA preloader partition hashes matched their manifests. See [ARM disassembly findings](docs/arm-range-check-analysis.md), [signature/load ordering](docs/tee-load-signature-order.md), [TEE header address processing](docs/tee-header-address-processing.md), and [SRAM target intersection](docs/sram-guard-exploit-intersection.md).

Do not flash Donut images to Crumpet or modify NAND partitions based on these findings.

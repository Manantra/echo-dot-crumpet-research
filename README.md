# Echo Dot 3 Refresh (Crumpet) — Research

Public, community-oriented **read-only reverse-engineering research** for the Amazon Echo Dot 3rd Gen Refresh (codename `crumpet`, model `C78MP8`).

> **Status: no independently confirmed persistent root, unlock or functional TWRP procedure for Crumpet.** This is not an unlock kit. **Do not flash Donut images to Crumpet.**

## What is known

- Crumpet uses **raw NAND**; the older Echo Dot 3 **Donut** uses a different boot/storage layout.
- Public [Crumpet UART logs](https://github.com/jvandewiel/no-alexa/tree/main/logicanalyzer/uart_logs) cover 2019 and 2021 preloaders.
- A [2019 raw-NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) is available. Whole-file SHA-256: `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`.
- **New (2026-10-08):** We verified and extracted **four March 2021 Crumpet preloader images** from Amazon's Fire OS 6.5.4.8 OTA, with their SHA-256 checksums validated against the official update manifest. [Full analysis](docs/ota-2021-analysis.md).
- **New (2026-10-08): Complete Crumpet NAND/GPT header decode.** We independently verified both CRC32s and **all 18 unchanged logical partition ranges from the public 2019 NAND excerpt through Nov 2025**. All 309 altered bytes in a May→Nov 2025 Preloader partition are **GPT disk/partition GUID bytes plus CRC32 fields**, not new Preloader code. The four redundant boot-copy BRLYT fields map exactly to their corresponding GPT first LBAs. **Not a root/recovery procedure.** [Detailed findings](docs/crumpet-nand-gpt-2019-2025.md).
- **Latest catalogued Crumpet OTA checked:** We verified November **2025** (Fire OS 6.5.7.1, NS6571/6208) and three earlier 2025 OTA images. `lk` remains **byte-identical to Jan 2024**; the full Preloader region from the MediaTek GFH header at `0x8000` is **identical across four 2025 updates** despite differing raw-NAND partition hashes. The **four Nov 2025 boot copies** also have identical GFH images, varying by only 4 position-related prefix bytes each. [Verified comparison](docs/latest-2025-ota-boot-payload-comparison.md).
- **New DA1→DA2 integrity and DA1 sync diagnostic finding:** Both bundled MT8167 DA1 variants embed the **SHA-1 of their own DA2 body** (signature excluded), not the other's. The upstream MTKClient DA1 setup function ignores `False` results from `sync()`, `setup_env()` and `setup_hw_init()`, yet may still log successful DA sync; independently reproduced with synthetic hardware-free mocks. [Detailed evidence](docs/da1-da2-pairing-handoff-checks.md).
- **Revision-match cross-check:** A reported Crumpet preloader has HW `0x8167`, subcode `0x8A00`, HW revision `0xCB00`, SW revision `1`; bundled DA metadata is `0xCA00/SW0`. MTKClient accepts older DAs. An independent same-revision MT8167 eMMC device reaches DA2 using a **same-named**, not hash-verified, V5 loader over **Preloader mode**. This contrasts with Crumpet's BROM/EMI timeout. [Version-matching audit](docs/mt8167-hw-revision-da-selection.md).
- **New Stage-2 handoff finding:** MTKClient's `Stage was't executed` message can be triggered by a missing/truncated **XFLASH USB status response**, not just device failure; the Crumpet's 2019/2021 UART logs show **256 MiB RAM at `0x40000000`**, with both DA2 code/BSS layouts fitting physically. [Status and memory analysis](docs/da2-handoff-status-memory.md).
- **DA2 binary + EMI research:** Both bundled MT8167 DA2 variants have ARM entry `0x40000024` and raw-NAND/BMT diagnostics, but distinct executable bodies. Independently verified official Crumpet 2021/2022/2024/2025 preloaders contain an **identical 400-byte EMI block (`MTK_BLOADER_INFO_v28`)**. No DA2 on Crumpet has been shown to boot. [Detailed binary analysis](docs/da2-binary-emi-compatibility.md).
- **MT8167 Download Agent research:** Source-code auditing identifies Stage-2 timeout as a missing response, **not proof** of DRAM or NAND failure. The bundled MTKClient has **two distinct 0x8167 DA binaries** (both targeting Stage-2 address `0x40000000`), but its version/duplicate selection normally retains only one. [Evidence and limits](docs/mtkclient-da-stage2-analysis.md).
- **Unlock research update:** Independently verified official `lk` binaries from **2021–2025** contain vendor `flash:unlock`, `flash:otucert`, `flash:otucode` strings. For the 2024/2025-identical `lk`, Thumb disassembly confirms the generic Fastboot dispatcher, the actual `unlock` validation call and one-time certificate/code handlers. No publicly validated accepted certificate or persistent Crumpet unlock exists. [Verified LK timeline](docs/lk-image-timeline.md) · [ARM unlock call graph](docs/lk-fastboot-unlock-disassembly.md).
- **Verified newer header-handling call chain:** the loader reads the 512-byte header, parses address/length, optionally transforms the TEE destination, checks protected memory ranges, then performs its larger read. The ATF/TEE verification wrapper follows the load. [Details](docs/tee-header-address-processing.md).
- **Key SRAM protection finding:** newer preloader builds guard BSS `[0x00102180, 0x00109DAC)`, which **contains the published payload's block-device target `0x001086EC`**. A hypothetical copy matching the payload's effective zero destination and size `0x00108804` intersects this protected region, so the new guard would reject it *if passed the actual copy address and size*. [Verified boundaries and conditional analysis](docs/sram-guard-exploit-intersection.md).
- **ARM analysis:** The 2022 preloader range checks and the 2023/2024-era rewritten text/BSS guards have been disassembled, with confirmed literal cross-references and calls. [Code analysis](docs/arm-range-check-analysis.md). This does not establish exploitable behaviour.
- **2023 build now obtained:** the exact Crumpet build string `20231103_072325` appears in preloader images verified from official 2025 OTAs. The image's full hash differs from a community device dump, so bitwise equivalence is **not** claimed. [Verified version timeline](docs/verified-preloader-timeline.md).
- [`amonet-koboreru`](https://github.com/R0rt1z2/amonet-koboreru) has Crumpet-specific code; its maintainer says the NAND port has **not been tested on real hardware** and is on hold.
- A [TWRP device tree](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167) exists, but a working Crumpet recovery is **not demonstrated**.

## Where to start

- [Research status and evidence levels](STATUS.md)
- **[Fully decoded Crumpet raw-NAND GPT container, valid CRCs, 2019–2025 stable layout, four boot-copy offsets](docs/crumpet-nand-gpt-2019-2025.md)**
- **[Latest 2025 Crumpet LK/Preloader proof: full hash changes occur only in NAND prefix](docs/latest-2025-ota-boot-payload-comparison.md)**
- **[DA1↔DA2 cryptographic pairing, BROM vs Preloader setup, and unchecked DA1 results](docs/da1-da2-pairing-handoff-checks.md)**
- **[MTKClient MT8167 DA Stage-2 timeout: source-code analysis](docs/mtkclient-da-stage2-analysis.md)**
- **[MT8167 DA2 executable comparison and verified 2021–2025 Crumpet EMI block](docs/da2-binary-emi-compatibility.md)**
- **[XFLASH status protocol, USB exception handling and Crumpet's measured 256 MiB DRAM](docs/da2-handoff-status-memory.md)**
- **[HW 0xCB00/SW1 Crumpet versus DA revisions, plus independent MT8167 Stage-2 counterexample](docs/mt8167-hw-revision-da-selection.md)**
- **[Verified LK firmware chronology: 2021–2025](docs/lk-image-timeline.md)**
- **[Decoded vendor LK Fastboot unlock/certificate call graph](docs/lk-fastboot-unlock-disassembly.md)**
- **[Current Crumpet root/unlock feasibility assessment (2026-10-08): verified LK certificate code, BROM limitations and NAND recovery](docs/root-unlock-feasibility-2026-10-08.md)**
- [Boot chain and exploit preconditions](docs/boot-chain.md)
- [Preliminary preloader binary analysis](docs/preloader-analysis.md)
- [Verified 2021 OTA partition inventory, SHA-256 hashes and 2019 comparison](docs/ota-2021-analysis.md)
- [Verified 2021–2025 preloader version timeline and byte differences](docs/verified-preloader-timeline.md)
- [ATF/TEE loading and signature verification: decoded ARM call chains](docs/tee-load-signature-order.md)
- **[TEE header fields and conditional address calculation: guard-before-read trace](docs/tee-header-address-processing.md)**
- **[SRAM/BSS guard versus the published exploit: decoded protection limits](docs/sram-guard-exploit-intersection.md)**
- **[ARM-disassembled old-vs-new memory-range guards, with cross-references and call sites](docs/arm-range-check-analysis.md)**
- [Open technical questions](research/open-questions.md)
- [Sources and attribution](references/sources.md)
- [How to contribute](CONTRIBUTING.md)

## Read-only Python tools

```bash
python3 scripts/preloader_forensics.py --fetch-2019
python3 scripts/preloader_compare.py older.bin newer.bin
python3 scripts/audit_sram_guard.py /path/to/local-2023-era-preloader.bin
python3 scripts/inspect_guard_chain.py /path/to/local-2023-era-preloader.bin
python3 scripts/trace_preloader_calls.py /path/to/local-2023-era-preloader.bin --begin 0x20df40 --length 0xe0 --target 0x20f3ac --target 0x216100
python3 scripts/ota_inventory.py /path/to/original-crumpet-ota.bin --verify-bootloaders
python3 scripts/remote_ota_probe.py 'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin' --include-lk
# Optional: install Capstone to disassemble a locally obtained preloader
# python3 -m pip install capstone
python3 scripts/disassemble_preloader.py /path/to/local-preloader.bin --address 0x20e3d8 --length 0x2a
# For the exact sha256-pinned official Crumpet LK from Jan 2024 / May 2025:
python3 scripts/inspect_lk_unlock.py /path/to/local-lk.bin
# Purely offline: analyze an EXISTING redacted MTKClient log (no device access)
python3 scripts/classify_mtkclient_stage2.py /path/to/saved-mtkclient.log
# Read-only decoder for a previously captured 12-byte XFLASH status frame + payload
python3 scripts/decode_xflash_status.py --hex 'efeeee fe 01000000 04000000 53594e43'
# Purely offline: inspect your local MTKClient DA loader folder
python3 scripts/audit_mtkclient_da_metadata.py /path/to/mtkclient/mtkclient/Loader --device-hwver 0xcb00 --device-swver 1 --device-subcode 0x8a00
python3 scripts/audit_da_pair_integrity.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_xflash_mode_flow.py /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py
# Official Amazon OTA Range reads, comparing only hashes/offsets (no saved binaries)
python3 scripts/compare_official_preloader_payloads.py OLDER_AMAZON_OTA_URL NEWER_AMAZON_OTA_URL
python3 scripts/compare_official_boot_copies.py AMAZON_CRUMPET_OTA_URL
# Validate embedded GPT CRCs and boot-copy headers (only reads official OTA)
python3 scripts/audit_nand_boot_gpt.py --official-ota AMAZON_CRUMPET_OTA_URL --copy 0
# Or analyze the publicly archived 2019 excerpt with its earlier byte offsets
python3 scripts/audit_nand_boot_gpt.py --image /path/to/2019/brhgptpl_0.bin
python3 scripts/audit_da_stage2.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_preloader_emi.py /path/to/local-crumpet-preloader.bin
python3 -m unittest discover -s tests -v
```

All tools only inspect input bytes and print findings; they do **not** communicate with devices or flash firmware. The forensics tool's optional fetch retrieves a public reference file over HTTPS. Missing strings or simplistic file-offset calculations cannot establish exploitability.

## Scope and safety

This repo hosts original research notes and non-destructive scripts only. **No Amazon firmware dumps, private identifiers, secrets, or unverified flash instructions.** Please label observations vs community reports vs hypotheses; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Original research documentation and scripts in this repository are provided under MIT. Third-party works remain with their original authors.

# Echo Dot 3 Refresh (Crumpet) — Research

Public, community-oriented **read-only reverse-engineering research** for the Amazon Echo Dot 3rd Gen Refresh (codename `crumpet`, model `C78MP8`).

> **Status: no independently confirmed persistent root, unlock or functional TWRP procedure for Crumpet.** This is not an unlock kit. **Do not flash Donut images to Crumpet.**

## What is known

- Crumpet uses **raw NAND**; the older Echo Dot 3 **Donut** uses a different boot/storage layout.
- Public [Crumpet UART logs](https://github.com/jvandewiel/no-alexa/tree/main/logicanalyzer/uart_logs) cover 2019 and 2021 preloaders.
- A [2019 raw-NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) is available. Whole-file SHA-256: `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`.
- **New (2026-10-08):** We verified and extracted **four March 2021 Crumpet preloader images** from Amazon's Fire OS 6.5.4.8 OTA, with their SHA-256 checksums validated against the official update manifest. [Full analysis](docs/ota-2021-analysis.md).
- **Key SRAM protection finding:** newer preloader builds guard BSS `[0x00102180, 0x00109DAC)`, which **contains the published payload's block-device target `0x001086EC`**. A hypothetical copy matching the payload's effective zero destination and size `0x00108804` intersects this protected region, so the new guard would reject it *if passed the actual copy address and size*. [Verified boundaries and conditional analysis](docs/sram-guard-exploit-intersection.md).
- **ARM analysis:** The 2022 preloader range checks and the 2023/2024-era rewritten text/BSS guards have been disassembled, with confirmed literal cross-references and calls. [Code analysis](docs/arm-range-check-analysis.md). This does not establish exploitable behaviour.
- **2023 build now obtained:** the exact Crumpet build string `20231103_072325` appears in preloader images verified from official 2025 OTAs. The image's full hash differs from a community device dump, so bitwise equivalence is **not** claimed. [Verified version timeline](docs/verified-preloader-timeline.md).
- [`amonet-koboreru`](https://github.com/R0rt1z2/amonet-koboreru) has Crumpet-specific code; its maintainer says the NAND port has **not been tested on real hardware** and is on hold.
- A [TWRP device tree](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167) exists, but a working Crumpet recovery is **not demonstrated**.

## Where to start

- [Research status and evidence levels](STATUS.md)
- [Boot chain and exploit preconditions](docs/boot-chain.md)
- [Preliminary preloader binary analysis](docs/preloader-analysis.md)
- [Verified 2021 OTA partition inventory, SHA-256 hashes and 2019 comparison](docs/ota-2021-analysis.md)
- [Verified 2021–2025 preloader version timeline and byte differences](docs/verified-preloader-timeline.md)
- [ATF/TEE loading and signature verification: decoded ARM call chains](docs/tee-load-signature-order.md)
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
python3 scripts/trace_preloader_calls.py /path/to/local-2023-era-preloader.bin --begin 0x20df40 --length 0xe0 --target 0x20f3ac --target 0x216100
python3 scripts/ota_inventory.py /path/to/original-crumpet-ota.bin --verify-bootloaders
python3 scripts/remote_ota_probe.py 'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin'
# Optional: install Capstone to disassemble a locally obtained preloader
# python3 -m pip install capstone
python3 scripts/disassemble_preloader.py /path/to/local-preloader.bin --address 0x20e3d8 --length 0x2a
python3 -m unittest discover -s tests -v
```

All tools only inspect input bytes and print findings; they do **not** communicate with devices or flash firmware. The forensics tool's optional fetch retrieves a public reference file over HTTPS. Missing strings or simplistic file-offset calculations cannot establish exploitability.

## Scope and safety

This repo hosts original research notes and non-destructive scripts only. **No Amazon firmware dumps, private identifiers, secrets, or unverified flash instructions.** Please label observations vs community reports vs hypotheses; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Original research documentation and scripts in this repository are provided under MIT. Third-party works remain with their original authors.

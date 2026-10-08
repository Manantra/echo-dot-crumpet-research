# Primary sources and attribution

- [R0rt1z2/amonet-koboreru](https://github.com/R0rt1z2/amonet-koboreru) — exploit source, **untested** Crumpet support.
- [Crumpet patch source](https://github.com/R0rt1z2/amonet-koboreru/blob/main/devices/crumpet.c).
- [MTKClient (pinned 2026-09-12 code)](https://github.com/bkerler/mtkclient/tree/cd25cf9) — hardware 0x8167 XFLASH mapping, DRAM response semantics, stage-2 exception and DA version selection.
- [Crumpet DA2 handoff and 256 MiB DRAM analysis](../docs/da2-handoff-status-memory.md) — normal-boot UART memory map, USB status decoding, exception semantics.
- [Read-only XFLASH status packet decoder](../scripts/decode_xflash_status.py) — synthetic and previously captured status frames only.
- [Direct DA2 executable and Crumpet EMI compatibility research](../docs/da2-binary-emi-compatibility.md) — verified ARM boot entry, bundled NAND markers and identical official 400-byte EMI trailer across 2021–2025.
- [Our MTKClient Stage-2 forensic report](../docs/mtkclient-da-stage2-analysis.md) — host status messages, two DA binaries, duplicate-selection finding and read-only reproduction.
- [Upstream issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2) — maintainer's NAND/recovery warning and community BROM/DA tests.
- [Public 2019 NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin).
- [2019 Crumpet UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt).
- [2021 Crumpet UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/normal_boot.txt).
- [TWRP device-tree project](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167) — source exists, **not** confirmed working for Crumpet.
- [Crumpet OTA index](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json) — official 2021 download URL, archived MD5 and historic metadata.
- [Decoded ATF/TEE load vs verification ordering](../docs/tee-load-signature-order.md) — direct Thumb call sites.
- [Verified SRAM/BSS bounds and published payload target](../docs/sram-guard-exploit-intersection.md) — conditional conclusion grounded in official binaries and upstream `create_tee_image.py`.
- [Upstream payload generator](https://github.com/R0rt1z2/amonet-koboreru/blob/main/create_tee_image.py) — exact Crumpet payload size calculation.
- [Verified 2021–2025 Crumpet preloader timeline](../docs/verified-preloader-timeline.md) — source URLs, build strings, hashes, and binary comparisons.
- [September 2021 Crumpet OTA — our verified analysis](../docs/ota-2021-analysis.md) — OTA manifest, all four preloader SHA-256s and non-destructive reproduction.
- [Verified Crumpet LK firmware timeline](../docs/lk-image-timeline.md) — SHA-256-verified 2021–2025 LK builds and code-region comparisons.
- [Amazon vendor LK unlock call graph](../docs/lk-fastboot-unlock-disassembly.md) — verified Thumb string cross-references and certificate-gated Fastboot control flow.
- [LibreEcho hardware roadmap](https://dev.libreecho.org/) — claims Crumpet access, but links to untested upstream amonet port; not independent proof.
- [October 2026 Crumpet research assessment](../docs/root-unlock-feasibility-2026-10-08.md) — independent community report, verified LK certificate-related strings, BROM limitations, NAND recovery research.
- [Crumpet Fastboot research wiki](https://github.com/jvandewiel/no-alexa/wiki/Fastboot) — locked fastboot response and one-time unlock certificate failure.
- [Crumpet NAND dumping and decoding wiki](https://github.com/jvandewiel/no-alexa/wiki/Decoding-NAND-flash) — BCH/PRBS details.
- [mtk-nand-utils (external, GPL/AGPL)](https://github.com/gilderchuck/mtk-nand-utils) — published NAND raw flash decode utilities.
- [Android update-engine manifest schema](https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto) — public protobuf field specifications.

Do not upload copyrighted firmware, secrets or private device identifiers.

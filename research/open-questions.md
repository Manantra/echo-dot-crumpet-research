# Open questions

1. **Partly resolved:** official 2025 Crumpet OTAs supply full `brhgptpl_*` images with the **2023 build string `20231103_072325`**. Their image hashes differ from the community-device dump SHA-256 `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`. Determine if this comes from formatting, per-device differences, or other content before claiming identity.
2. **Partly resolved:** entry-point mapping validated from the `FILE_INFO` load address and ARM branch of the stored images. Independently establish live relocation/runtime execution layout, particularly for the 2019 NAND excerpt.
3. **Partly resolved:** 2022-vs-2023-built memory-range checks have been disassembled with cross-references to the logged diagnostics and loader call sites ([analysis](../docs/arm-range-check-analysis.md)). Next: determine full call-chain order relative to TEE verification, compare 2019, and inspect anti-rollback/DA-verification routines at validated addresses.
4. **Resolved (2026-10-08):** Official September 2021 OTA contains four `brhgptpl_*` preloader entries, all extracted and SHA-256 verified. See [results](../docs/ota-2021-analysis.md). Next: carefully map 2021 image addresses and compare functions against 2019.
5. Explain the BROM/MTKClient DA stage 2 failure without writing anything.
6. Investigate why upstream Crumpet specifies `expdb` where a logged partition table lacks it.
7. Determine whether a raw-NAND-specific TWRP port is possible and recoverable.
8. **Partly resolved:** the updated guard's encoded BSS interval `[0x00102180,0x00109DAC)` contains the published payload's BDEV target `0x001086EC`; its `0x00108804` data extent would overlap protected BSS if the effective destination is zero. [Static source/bin check](../docs/sram-guard-exploit-intersection.md). **Still open:** verify exact `0xFFFFFFFF` header-address fallback and length propagation to `0x20F490` on all paths, including early reads; do not assume exploitability or full mitigation without this proof.

No destructive testing without a validated recovery mechanism.

# Open questions

1. Obtain a lawful, sharable copy of the **2023 Crumpet preloader** and independently verify SHA-256 `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`.
2. Establish the correct NAND-to-memory mapping and execution entry points of the 2019 image.
3. Compare overlap, anti-rollback and DA verification routines in the *actual machine code* of the **available 2019 and 2021 binaries**, then compare with 2023 if obtained.
4. **Resolved (2026-10-08):** Official September 2021 OTA contains four `brhgptpl_*` preloader entries, all extracted and SHA-256 verified. See [results](../docs/ota-2021-analysis.md). Next: carefully map 2021 image addresses and compare functions against 2019.
5. Explain the BROM/MTKClient DA stage 2 failure without writing anything.
6. Investigate why upstream Crumpet specifies `expdb` where a logged partition table lacks it.
7. Determine whether a raw-NAND-specific TWRP port is possible and recoverable.

No destructive testing without a validated recovery mechanism.

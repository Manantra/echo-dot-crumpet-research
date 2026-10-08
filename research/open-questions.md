# Open questions

1. Obtain a lawful, sharable copy of the **2023 Crumpet preloader** and independently verify SHA-256 `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`.
2. Establish the correct NAND-to-memory mapping and execution entry points of the 2019 image.
3. Compare overlap, anti-rollback and DA verification routines in the *actual machine code* of 2019/2023.
4. Inspect an archived 2021 OTA **read-only** to determine whether it contains a preloader.
5. Explain the BROM/MTKClient DA stage 2 failure without writing anything.
6. Investigate why upstream Crumpet specifies `expdb` where a logged partition table lacks it.
7. Determine whether a raw-NAND-specific TWRP port is possible and recoverable.

No destructive testing without a validated recovery mechanism.

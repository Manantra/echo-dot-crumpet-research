# Hypotheses — not proven

- **Patch-address mismatch:** the public 2019 NAND excerpt may differ from the firmware build expected by today's upstream Crumpet payload. Runtime address translation has **not** been validated.
- **String discrepancy:** `check_part_overlapped done` occurs in 2019 UART but is absent from public 2019 binary excerpt. Possible causes include missing regions, separate firmware components, or build differences.
- **NAND partition mismatch:** `expdb` is hardcoded as a destination for custom LK in one upstream config, but absent in a logged NAND partition table.
- **TWRP storage mismatch:** shared recovery fstab/init files reference `mmcblk0boot0` and MMC by-name paths, which do not directly describe the observed raw-NAND layout.

Please test hypotheses only with non-destructive evidence or fully recoverable dedicated research hardware.

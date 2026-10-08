# Hardware facts and limits

**Crumpet** is the Echo Dot 3rd Gen Refresh (often model **C78MP8**). It uses **raw NAND** and should not be conflated with earlier **Donut**, which has different storage/boot behavior.

MTKClient reports hardware code `0x8167` on devices in [upstream issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2). Some source projects label related MTK platform support `mt8516`; that naming by itself is not proof of a different chip.

A public 2019 [UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) identifies NAND `MX30LF4G28AD`, bad-block handling, and a partition table containing `lk_a`, `lk_b`, `tee1`, `tee2`, `boot_a`, `boot_b`, `userdata`.

These observations apply to the specifically logged hardware; other revisions must be checked independently.

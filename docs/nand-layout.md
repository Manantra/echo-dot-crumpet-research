# Raw NAND layout in a public 2019 Crumpet log

The documented partition-name sequence is:

`brhgptpl_0`, `reserve0`, `lk_a`, `lk_b`, `brhgptpl_1`, `reserve1`, `idme_nand`, `brhgptpl_2`, `reserve2`, `misc`, `brhgptpl_3`, `reserve3`, `tee1`, `boot_a`, `tee2`, `boot_b`, `persist`, `userdata`.

Source: [jvandewiel/no-alexa 2019 UART](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt).

This is a historical observation, **not** a flash layout prescription. Public `brhgptpl_0.bin` is 196,608 bytes while logged partition span is 262,144 bytes; it may be only a partial excerpt.

The shared [TWRP device tree](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167) contains eMMC-specific recovery paths not directly compatible with this raw-NAND example.

# Preloader analysis (preliminary)

A public [Crumpet NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) is 196,608 bytes with SHA-256 `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637` (whole file). It contains `BOOTLOADER!`, MediaTek `MMM/FILE_INFO` headers, `crumpet` and a 2019 build stamp.

The **2019 and 2021 UART logs** both mention `check_part_overlapped done`. The literal string was not found in the available public 2019 NAND excerpt. The 2023 build's absence of the same string is *community-reported*. **A missing string is not proof that a vulnerability is fixed.**

Candidate translations of upstream runtime address `0x00217F2C` to offsets within the 2019 excerpt landed in ASCII data. This is a **hypothesis of version/layout mismatch**, not a verified runtime mapping: the NAND file contains multiple wrapper headers and possibly omits regions of the partition.

The full 2023 preloader binary is not available for analysis; we have not completed a 2019-vs-2023 function-level disassembly.

See [2019 UART](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) and [2021 UART](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/normal_boot.txt).

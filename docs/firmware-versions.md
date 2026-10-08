# Firmware and preloader timeline

| Build | Direct evidence | Interpretation |
|---|---|---|
| `20190926_190455` | [UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) and [NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) | Old Crumpet build; overlap diagnostic visible in **UART**, not literal in public NAND excerpt |
| `20210326_040236` | [UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/normal_boot.txt) | Overlap diagnostic appears |
| `20231103_072325` | [Multiple issue reports](https://github.com/R0rt1z2/amonet-koboreru/issues/2) | Public reported SHA-256: `d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`; binary not independently obtained |

[FTVDB's firmware catalogue](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json) lists historic Crumpet OTA packages from 2021 onward. **No claim is made that those OTA packages contain a preloader or that they were unpacked for this project.**

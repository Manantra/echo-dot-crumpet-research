# Firmware and preloader timeline

| Build | Direct evidence | Interpretation |
|---|---|---|
| `20190926_190455` | [UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) and [NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) | Old Crumpet build; overlap diagnostic visible in **UART**, not literal in public NAND excerpt |
| `20210326_040236` | [UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/normal_boot.txt) **and four verified `brhgptpl_*` images extracted from an official 2021 OTA** | Overlap diagnostic at `0x26DEA`; four independently verified partition SHA-256s; [full results](ota-2021-analysis.md) |
| `20220323_062523` | November 2022 and June 2023 official OTAs | Central firmware image region **identical** across the two versions; overlap diagnostic is present |
| `20230726_065225` | January 2024 official OTA | Overlap diagnostic absent; large binary changes from June 2023 |
| `20231103_072325` | May and November 2025 official OTAs; [community reports](https://github.com/R0rt1z2/amonet-koboreru/issues/2) | Build **independently obtained**; OTA image hash differs from the reported device-dump hash (`d0d43eea2d5d52835007e375a3214fa4c6bf1a7c319e52ab442b7567e318992b`) |

[FTVDB's firmware catalogue](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json) lists historic Crumpet OTA packages from 2021 onward. **The September 2021 OTA was downloaded, integrity-checked and its four preloader partition images reconstructed without flashing.** See [analysis and reproducible tool](ota-2021-analysis.md). Several more OTA versions (Nov 2022, Jun 2023, Jan 2024, May/Nov 2025) were examined with HTTP Range requests and per-image SHA-256 verification. See the [complete verified timeline](verified-preloader-timeline.md).

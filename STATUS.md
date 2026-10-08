# Research status — 2026-10-08

**No proven persistent unlock, root or TWRP for Crumpet (C78MP8).** This repository is research, not a flash guide.

| Topic | Evidence level | Status |
|---|---|---|
| Raw NAND storage | Documented in 2019 Crumpet logs | Confirmed for logged hardware |
| Preloader 2019: `20190926_190455` | Public NAND excerpt and UART logs | Verified source material |
| Preloader 2021: `20210326_040236` | UART logs | Documented |
| Preloader 2023: `20231103_072325` | Independent community reports | Binary unavailable to us |
| BROM/Kamakiri on some Crumpets | User reports | Reported, not a root method |
| Download Agent stage 2 | User reports | Fails on tested devices |
| Crumpet amonet-koboreru port | Author statement | Not tested on actual device |
| 2019→2023 machine-code comparison | No 2023 binary | Not performed |
| Runtime patch-address mapping | File/image wrappers unresolved | Hypothesis only |
| TWRP for raw NAND Crumpet | Existing shared device tree | Not demonstrated |

Do not flash Donut images to Crumpet or modify NAND partitions based on these findings.

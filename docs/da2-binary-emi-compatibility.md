# Direct MT8167 DA Stage-2 binary and Crumpet EMI compatibility comparison

**Date:** 2026-10-08. **Research method:** locally cloned [MTKClient revision `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9), offline ARM instruction decoding, inspection of raw loader metadata, and retrieval of only four official Amazon Crumpet OTA preloader components via HTTPS byte ranges. **No device connected. No ARM payload executed. No DA uploaded. No NAND access.**

This builds on our [source-code audit of the Stage-2 timeout](mtkclient-da-stage2-analysis.md). The key question is whether the alternate MT8167 DA actually has a different start-up path, and whether public Crumpet firmware provides incompatible DRAM initialization blobs.

## 1. Actual MT8167 download-agent code, not merely metadata

The bundled MTKClient Loader directory contains **two different ARM32 executable DA bundles targeting hardware `0x8167`**, with identical subcode `0x8A00` and HW version `0xCA00`.

| Property | MTK_DA_V5.bin | MTK_AllInOne_DA_mt6590.bin |
|---|---|---|
| Full file SHA-256 | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` |
| DA1 region size, including signature | `0x27188` (160136 bytes) | `0x21B6C` (138092 bytes) |
| DA1 load address | `0x00200000` | `0x00200000` |
| DA2 region size, including signature | `0x55A98` (350872 bytes) | `0x31698` (202392 bytes) |
| DA2 load address | `0x40000000` | `0x40000000` |
| Declared DA1 / DA2 signature tail | `0x100` / `0x100` | `0x100` / `0x100` |
| DA1 initial ARM branch | `0x00200004` | `0x00200004` |
| DA2 initial ARM branch | `0x40000024` | `0x40000024` |

The DA1 and DA2 initial control-transfer locations were computed from the first **ARM unconditional branch instruction** of each matching executable region. The DA2 initial branch instruction, `0xEA000007`, targets `0x40000024` for both files. The first **244 bytes** of their DA2 executable bodies match, followed by substantial differences.

### More precise difference in the ARM startup memory layout

Both DA2 images use the same ARM reset/init loop from `0x40000024` through `0x400000F0`. This decoded sequence copies relocatable data, sets CPU mode-specific stack pointers, and zero-initializes BSS. **The first differing binary word is at file offset `0xF4`**, where the image calls a different next-stage function. Other immediately following differences are **literal pointers**, not evidence that the common startup logic itself was rewritten.

The decoded `LDR`/comparison/`STRLT` loop at ARM addresses `0x400000D4`–`0x400000E8` loads its zero-fill boundaries from literal values at image offsets `0x11C` and `0x120`. These provide exact **static BSS spans**:

| DA2 build | Zero-initialized BSS start | BSS end, exclusive | Clear length |
|---|---|---|---|
| V5 | `0x400559A0` | `0x4006A520` | `0x14B80` bytes |
| Alternative | `0x400315A0` | `0x400456E0` | `0x14140` bytes |

Both remain within the ordinary `0x40000000`-based DRAM address space, but the **required occupied regions differ**, along with the branch into later initialization code. The report cannot infer that Crumpet actually has insufficient DRAM for the larger build from these addresses alone.

The updated `audit_da_stage2.py` independently recovers these ranges **only after verifying the expected ARM opcodes** for the BSS-clearing loop. Synthetic tests additionally confirm that altered opcodes prevent a false BSS inference.

The signature-tailed regions were parsed and independently SHA-256 checked against their local source files. For independent cross-check:

| Executable region | V5 SHA-256, including signature | Alternative SHA-256, including signature |
|---|---|---|
| DA1 | `bdea0c74a9342954622124adeb0acec541157eccee80dea042a8779f1111ac53` | `993fe4403f86692bfca54082b3f92ecfa5794e4ec0dbc1597981815831b69ea3` |
| DA2 | `8b83084d449c92153c28e4dc466a50b6d3a286c3fe1454d4de8015a3bd5ce33b` | `35e3aa09a4edd226fe33e266fdde3437c48b3268c0ab085d9a9dc32150c64755` |

### NAND capability is present in *both* DA2 binaries

A read-only ASCII search of the DA2 executable regions confirms:

- **Both** contain NAND diagnostics and bad-block-management ("BMT") messages.
- V5 contains `nandx_chip_cache_program`-family names and extensive `[BMT]` / `nand` diagnostics.
- The alternative contains NAND controller register diagnostics and `[BMT]` handling, including "Load bmt data" and "ECC config Wrong!".
- A simple reproducible marker counter yields V5 **72 NAND-diagnostic and 15 BMT marker occurrences**, versus the alternative's **23 NAND-diagnostic and 6 BMT occurrences**. These numbers depend on exact searched byte substrings and are **not** measures of feature completeness, supported NAND chip IDs, or functional quality.

**Interpretation:** DA2 is *not* excluded simply because Crumpet uses raw NAND, and neither candidate is demonstrated compatible just because it contains controller-driver messages. The Stage-2 timeout happens before the host's subsequent NAND-info handshake.

## 2. Exactly the same official Crumpet EMI block in four firmware builds

We independently obtained each official Amazon preloader component via HTTP byte range, validated the compressed-operation SHA-256 and final preloader SHA-256 against the original CrAU manifest, then parsed the MTK `MMM/FILE_INFO` header and the EMI trailer following the method in [MTKClient `daconfig.m_extract_emi`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L120-L165).

| OTA publication | Encoded preloader build | EMI version | EMI length | EMI SHA-256 |
|---|---|---|---:|---|
| Sep 2021 | `20210326_040236` | `MTK_BLOADER_INFO_v28` | 400 bytes | Same |
| Nov 2022 | `20220323_062523` | `MTK_BLOADER_INFO_v28` | 400 bytes | Same |
| Jan 2024 | `20230726_065225` | `MTK_BLOADER_INFO_v28` | 400 bytes | Same |
| May 2025 | `20231103_072325` | `MTK_BLOADER_INFO_v28` | 400 bytes | Same |

**Common SHA-256 for the complete 400-byte EMI trailer:**

`c2a394668216e8bc20959bef29aee38002854a0b38444f6fcd9877fd5d548120`

The four underlying **whole preloader images have different SHA-256 hashes**; only the extracted EMI trailer is demonstrably identical.

**Implication:** For these official firmware versions, merely substituting a 2021 versus a 2025 preloader as an EMI source does **not** supply different bytes to MTKClient's EMI initialization path. This substantially weakens a hypothesis that the Crumpet Stage-2 failure is due solely to choosing one of these historical EMI blocks.

**Caveats:** The identical EMI trailer does **not** independently test that actual DRAM is stable, confirm every board revision uses identical DRAM, rule out DA1/DA2-specific EMI interpretation differences, or identify what happened in a third party's individual failed session.

## 3. Download Agent selection and version compatibility

At [MTKClient `daconfig.py` lines 100–120 and 192–220](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L100-L220), discovered Loader file names are processed in descending order and matching DA records can be treated as duplicates when their HW and SW version fields match. Consequently the `0x8167` entry in **`MTK_DA_V5.bin`** is normally selected and **`MTK_AllInOne_DA_mt6590.bin`** is suppressed for the same version tuple.

There is also a tautological subcode comparison `da.hw_sub_code == da.hw_sub_code` instead of comparing to the previous record. **The two DA entries above already have the same subcode**, so the tautology is a separate source bug, not the immediate reason this particular pair is considered duplicate.

It is **not established** whether different DA1/DA2 revisions, different controller-initialization routines, a memory-layout mismatch, USB state at the handoff or a device-side security decision explains Crumpet's observed missing Stage-2 reply.

## 4. Reproduction without flash or image export

Using a separately obtained copy of **MTKClient source** and the corresponding bundled `mtkclient/Loader` directory:

```bash
python3 scripts/audit_mtkclient_da_metadata.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_da_stage2.py /path/to/mtkclient/mtkclient/Loader
```

With an already-obtained official Crumpet preloader image, the EMI metadata can be independently verified without exporting the EMI payload:

```bash
python3 scripts/audit_preloader_emi.py /path/to/official-crumpet-preloader.bin
```

For earlier MTKClient logs, the safe diagnostic workflow is:

```bash
python3 scripts/classify_mtkclient_stage2.py /path/to/redacted-existing-mtkclient.log
python3 -m unittest discover -s tests -v
```

All scripts are local, read-only analyzers. No Amazon or MediaTek binaries are redistributed here. Checks of code-entry branches, markers and hashes do **not** imply verified execution on Crumpet.

## 5. Next discriminating evidence

**High-value, non-destructive information from an already captured failed session:**

1. Selected DA **filename and version/hash**; upstream default filename order is not a substitute for knowing the selected file.
2. Whether the input EMI trailer matches the above hash, or another source was supplied.
3. Whether the client reached the Stage-1 sync and `INIT_EXT_RAM` response, plus the **exact exception class** on the subsequent Stage-2 status read.
4. Host USB re-enumeration/disconnect timing during that handoff, if already logged.
5. Full device-specific DA2 compatibility assessment (controller, chip IDs and actual memory handoff); a string search alone is insufficient.

**Research priority:** compare the **initialization/handoff differences** in the two DA builds offline. Do **not** try random DA uploads, test-point manipulation, NAND writes, or downgrade without a validated and independently reproducible recovery procedure.

**Current result:** A working DA Stage-2, recoverable NAND access and Crumpet root/unlock are **not yet demonstrated**.

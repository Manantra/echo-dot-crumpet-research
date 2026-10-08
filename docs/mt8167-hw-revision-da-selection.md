# MT8167 Crumpet DA hardware-version mismatch: independently falsifying an overly simple cause

**Date:** 2026-10-08. **Nature:** read-only comparison of Crumpet third-party logs, bundled MTKClient DA records, actual MTKClient loader-selection code, and an independent MT8167 Stage-2-success report. No hardware uploads, flash operations, or authorizations.

## 1. Actual Crumpet device tuple versus the bundled DA metadata

A contributor in [upstream Crumpet issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2) reports a real device queried through the preloader USB serial connection:

```text
HW code (separate command) = 0x8167
GET_HW_SW_VER response (four big-endian 16-bit fields):
  HW subcode 0x8A00
  HW version 0xCB00
  SW version 0x0001
  extra field 0x0000
```

The exact structure agrees with [MTKClient `mtk_preloader.get_hw_sw_ver()`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/mtk_preloader.py#L928-L931), which sends `GET_HW_SW_VER` and unpacks the eight returned bytes using `>HHHH`.

Meanwhile, the only **two** `HW 0x8167` records found in the checked-out MTKClient `mtkclient/Loader` folder (source commit `cd25cf9`) are:

| Property | Reported real Crumpet | MTK_DA_V5.bin | MTK_AllInOne_DA_mt6590.bin |
|---|---|---|---|
| HW code | `0x8167` | `0x8167` | `0x8167` |
| Subcode | `0x8A00` | `0x8A00` | `0x8A00` |
| HW version | **`0xCB00`** | **`0xCA00`** | **`0xCA00`** |
| SW version | **`0x0001`** | **`0x0000`** | **`0x0000`** |

**This confirms a metadata version mismatch between at least one reported Crumpet and both built-in DA binaries.** The actual version tuple for the separate BROM/Kamakiri failure reporters was **not published together with their selected DA hashes**. It is not legitimate to assume the same mismatch explains their failures.

## 2. Why MTKClient selects an apparently older DA

Source: [MTKClient `daconfig.py`, `setup()`, lines 207–222](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L207-L222).

The selection uses:

```python
if loader.hw_version <= config.hwver or config.hwver == 0:
    if loader.sw_version <= config.swver or config.swver == 0:
        if config.da_loader is None:
            config.da_loader = loader
```

The filter **intentionally accepts older HW/SW version metadata**; it does not require exact equality. It also does not compare the reported hardware subcode during this final filter. With `0xCB00/0x0001`, both `0xCA00/0x0000` DA records pass. Default duplicate filtering / file order selects **`MTK_DA_V5.bin`** rather than exposing the alternate DA as another choice.

This is a prediction from the pinned MTKClient implementation, reproduced in the updated [read-only DA metadata auditor](../scripts/audit_mtkclient_da_metadata.py). It is **not a documented claim of safe forward binary compatibility**.

Reproduce locally:

```bash
python3 scripts/audit_mtkclient_da_metadata.py \
  /path/to/mtkclient/mtkclient/Loader \
  --hw 0x8167 --device-hwver 0xcb00 --device-swver 1 --device-subcode 0x8a00
```

The output marks the chosen record and explicitly identifies any non-exact revision tuple. No binaries are uploaded or executed.

## 3. Strong *negative* evidence: another HW 0xCB00 / SW 1 MT8167 boots a DA with the same filename

An independent MTKClient trace in [bkerler/mtkclient issue #9, opened 2026-01-20](https://github.com/bkerler/mtkclient/issues/9) is from a **Pexar 2K digital picture frame**, not a Crumpet. It reports:

```text
HW 0x8167 / subcode 0x8A00 / HW version 0xCB00 / SW version 0x0001
DaHandler - Device is in Preloader-Mode.
DAXFlash - Uploading xflash stage 1 from MTK_DA_V5.bin
DAXFlash - Successfully received DA sync
DAXFlash - Uploading stage 2...
DAXFlash - Boot to succeeded.
DAXFlash - Successfully uploaded stage 2
DAXFlash - EMMC Boot1 Size: 0x400000
DAXFlash - EMMC USER Size: ...
DAXFlash - DA Extensions successfully added at 0x4fff0000
```

The later user command was stuck at `Main - Handling da commands ...` and its intended bootloader unlock did **not** complete. But the trace **independently demonstrates that MTKClient has run `MTK_DA_V5.bin` through a successful DA2 handshake on a device advertising exactly the same HW/sub/SW revisions as the reported Crumpet.** The Pexar report does not provide its DA binary's full SHA-256, so bit-for-bit identity with our MTKClient checkout cannot be established.

Therefore the claim `"all MT8167 0xCB00/SW1 devices must fail when MTKClient selects MTK_DA_V5.bin"` is directly contradicted by an actual independent device log.

### What is different from the failing Crumpet reports?

| Dimension | Pexar MT8167 (successful DA2) | Crumpet BROM reports (DA2 timeout) |
|---|---|---|
| Chip & some revision identifiers | `0x8167 / 0x8A00 / 0xCB00 / SW 1` | Chip `0x8167`; at least one Crumpet reports the same versions |
| Boot entry mode | **Preloader** | **BROM + Kamakiri** on failing units |
| DRAM/EMI preparation | XFLASH preloader connection; no explicit external EMI `send_emi` step in this path | XFLASH BROM connection; explicit EMI initialization acknowledged |
| Flash interface | **eMMC** | **Raw NAND** |
| DA selection | `MTK_DA_V5.bin` reported | Specific DA file + hash usually **not** in publicly reported failure summaries |
| DA2 outcome | DA2 success handshake + storage info | DA2 status exception/timeout |
| Persistent unlock | **Not achieved** in referenced issue | **Not achieved** |

**Inferences:**
- A simple older-DA-metadata rejection is **not enough** to explain the Crumpet-specific failure.
- The **different handoff mode/EMI path** is a stronger, evidence-based distinction to investigate.
- Raw NAND **may** matter to the DA's driver after Stage 2, but on Crumpet the failure is earlier, before NAND-info enumeration. Do not identify NAND itself as the cause.
- One successful unrelated MT8167 device does not prove that the same-named DA binary has identical bytes or will run on Crumpet. Actual RAM timing, board revision, secure state, and USB endpoint behavior still matter.

## 4. Specific next non-destructive work

1. Determine the selected DA version, filename and hash **from existing Crumpet traces**, rather than inferring it from repository defaults.
2. Audit the BROM `send_emi` handoff versus preloader-managed DRAM initialization at the host protocol and DA1 firmware levels, without uploading binaries.
3. Compare **existing** post-transfer USB endpoint and status-read exception logs from a Crumpet if available. `Stage was't executed` is an exception-collapsing message.
4. Check whether MTKClient has a newer compatible **legitimately distributed** 0x8167 loader; no exact `0xCB00/0x0001` record exists in the **two bundled** 0x8167 loader entries we inspected. Absence from this checkout does not prove no such DA exists elsewhere.

**No functional Crumpet root or unlock found.** The procedure is not safe to try on a single unrecoverable raw-NAND device without a validated restore path. No Amazon/MediaTek copyrighted boot binaries are stored in this repository.

# MT8167 Crumpet: MTKClient BROM → DA Stage-2 failure forensic audit

**Research date:** 2026-10-08. **Type:** read-only source-code and community-log analysis. No real device connected, no BROM payload transmitted, no NAND writes.

## Sources and tool version

We independently inspected [bkerler/mtkclient](https://github.com/bkerler/mtkclient) at Git commit **`cd25cf9` (2026-09-12)** and compared it with [Crumpet amonet-koboreru issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2). The community reports are not full packet captures; absence of a line in a submitted issue does not prove that a command was never run.

The relevant upstream code is pinned to the revision inspected:

- [MT8167 chip configuration](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/config/brom_config.py#L2289-L2313)
- [XFLASH DRAM/EMI command and stage-2 response handling](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L251-L321)
- [XFLASH DA upload, automatic EMI search, and stage-2 handoff](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L1097-L1167)
- [DA loader metadata selection and preloader EMI extraction](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L120-L225)
- [NAND identification after successful handoff](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L995-L1017)
- [Generic final `Failed to upload da` status](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/mtk_da_handler.py#L205-L209)

## Concrete findings

### 1. MT8167 isn't generically excluded from NAND

`brom_config.py` has an explicit `0x8167` `Chipconfig` labeled `MT8167/MT8516/MT8362`, with `damode=DAmodes.XFLASH` and `da_payload_addr=0x201000`. The XFLASH library has `get_nand_info()`, and `reinit()` selects `storage.flashtype="nand"` when NAND is returned.

**Therefore:** "MTKClient always assumes eMMC and cannot support NAND" is **incorrect as a blanket statement** for the inspected software. That does **not** guarantee the selected Download Agent binary implements the required raw-NAND hardware support.

### 2. Successful DA Stage 1 is separate from DRAM and Stage 2

The XFLASH path first uploads and jumps to DA Stage 1 and expects a `0xC0` synchronization byte followed by an XFLASH sync packet. The successful sync is printed by `upload_da1()` (`xflash_lib.py` lines 952–995).

Stage 2 is not running merely because these Stage-1 messages appear.

### 3. `DRAM setup passed.` means an EMI command was **acknowledged**

In `send_emi()` (`xflash_lib.py` lines 251–269), the library sends `INIT_EXT_RAM` plus the supplied EMI configuration bytes. On a successful `send_param()` status, it prints **`DRAM setup passed.`**.

It does **not** independently run DRAM stress tests or prove that a later stage-2 instruction fetch, data segment, cache configuration or memory handoff will work. Thus "DRAM setup passed" does not logically eliminate DRAM/EMI as a potential cause.

### 4. `Upload data was accepted. Jumping to stage 2...` is an acknowledgement **before** execution confirmation

In `boot_to()` (`xflash_lib.py` lines 288–321), the message follows successful `send_data(da)` and precedes the final response check. The implementation sleeps briefly and then requests a status packet.

On an **exception during that status read**, it prints **`Stage was't executed. Maybe dram issue ?.`**. This is a *generic exception/transport-status symptom*. It **does not positively identify** bad DRAM, raw-NAND incompatibility, a signature rejection or a patched BootROM. If the status returns a non-success value rather than throwing, a **different** error is emitted.

The later **`Failed to upload da.`** message is a generic wrapper in `mtk_da_handler.py`, not a second independent root-cause diagnosis.

### 5. Auto-EMI matching is eMMC-centric even though XFLASH has NAND support

In `upload_da()` (`xflash_lib.py` lines 1111–1144), if the connection agent is BROM and no preloader EMI data was obtained, MTKClient attempts to find a matching preloader in its loader directory using **eMMC CID**. It can inspect UFS metadata, but the later loop only tests an eMMC-CID match and logs **`No emmc info, can't parse existing preloaders.`** on the non-eMMC path.

**Evidence-backed limitation:** The inspected auto-selection branch lacks a NAND-ID-based preloader/EMI match. It may leave `emi=None` or choose no candidate on raw-NAND-only units. **However**, reported Crumpet sessions that actually print `DRAM setup passed.` already used a configuration accepted by Stage 1; this limitation is *not* sufficient to explain their subsequent Stage-2 timeout.

Potential alternative: A specific, compatible device Preloader / EMI blob and *matching* DA metadata may matter. We have **not** established which loader works on Crumpet and do not prescribe uploading an unverified file.

### 6. NAND capability cannot yet be inferred from the failed session

`get_nand_info()` is part of `reinit()`, which runs **only after Stage 2 returns success**. The Crumpet issue reports timeout before this point. Consequently its log is insufficient to show whether the chosen DA's NAND driver would work, even though the host library implements an NAND-info protocol.

### Newly verified: two different MT8167 DA binaries in the same upstream checkout

We parsed the **actual bundled DA loader metadata** from the cloned `bkerler/mtkclient` commit `cd25cf9` without executing or redistributing either DA.

| Loader filename | Full-file SHA-256 | DA1 bytes / load address | DA2 bytes / load address | Subcode / HW ver / SW ver |
|---|---|---|---|---|
| `MTK_DA_V5.bin` | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `0x27188` / `0x00200000` | `0x55A98` / `0x40000000` | `0x8A00` / `0xCA00` / `0x0000` |
| `MTK_AllInOne_DA_mt6590.bin` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` | `0x21B6C` / `0x00200000` | `0x31698` / `0x40000000` | `0x8A00` / `0xCA00` / `0x0000` |

Both records explicitly target `HW 0x8167`, have **three DA regions** and **0x100-byte DA1/DA2 signature sections**. The different Stage-2 sizes show these are **different** DA binaries, not identical duplicates. Each targets Stage-2 RAM address **`0x40000000`** in its own metadata. This location is a **DA loading address, not an instruction to flash the device**.

### Concrete DA selection limitation (source audit)

In [`daconfig.py` lines 100–120 and 192–219](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L100-L220), loader filenames are scanned in descending sort order, the first compatible entry is retained, and a later record with the same HW and SW versions may be treated as duplicate. Thus, under that repository's default filename order, **`MTK_DA_V5.bin` comes first and the alternative `MTK_AllInOne_DA_mt6590.bin` entry is suppressed** for the matching `0x8167` version tuple.

The duplicate suppression has an **actual source-code defect** at line 196:

```python
if da.hw_sub_code == da.hw_sub_code:
```

This self-comparison is tautologically true and does **not** compare `da.hw_sub_code` to `ldr.hw_sub_code`. It can incorrectly merge entries that differ *only* in subcode. **However, the two bundled `0x8167` entries listed above already share the same subcode `0x8A00`; that bug alone does not explain their suppression.** The first-compatible-entry/duplicate-version policy does.

**Impact on Crumpet remains unproven.** The issue logs do not pin the exact selected DA file hash, version, image-entry offsets or USB behavior at Stage-2 handoff. Nothing here demonstrates that attempting the alternative DA would work or be safe. The goal is **offline compatibility analysis**, not experimentally sending different DA binaries to irreplaceable hardware.

To reproduce with your own fresh **local MTKClient source checkout** (this tool reads only existing file metadata):

```bash
python3 scripts/audit_mtkclient_da_metadata.py /path/to/mtkclient/mtkclient/Loader
python3 -m unittest discover -s tests -v
```

The scanner checks loader record magic, hardware and software identifiers, section sizes, declared SRAM/DRAM addresses, file bounds, and per-file hashes. It predicts deduplication outcomes from the source logic. **It never connects to USB or writes files, devices or firmware.**

**Update (2026-10-08):** We subsequently compared the two DA2 ARM binaries directly and extracted four official Crumpet preloader EMI trailers read-only. All four EMI blocks are **identical** (400 bytes, `MTK_BLOADER_INFO_v28`, SHA-256 `c2a394668216e8bc20959bef29aee38002854a0b38444f6fcd9877fd5d548120`). Both DA2 images branch to `0x40000024` and contain NAND/BMT marker strings, but differ substantially elsewhere. See [DA2 and EMI compatibility report](da2-binary-emi-compatibility.md). This does **not** establish that the observed Stage-2 failure has been fixed.

## 7. Community-reported hardware states differ

The independent issue reports distinguish:

- Some units enumerate in **BROM** (`0e8d:0003`), execute Kamakiri, receive Stage-1 DA sync and then lose Stage-2 response.
- Another unit reports only **preloader mode** (`0e8d:2000`) and Fastboot (`0bb4:0c01`); BROM access was not observed, and attempts produced explicit `DA_IMAGE_SIG_VERIFY_FAIL (0x2001)` or `DA_INVALID_LENGTH (0x7004)`.
- The device owner reports from a single maintainer's issue do not constitute statistically reliable success rates for all Crumpet hardware revisions.
- A contributor's statement that the BootROM is patched and causes the crash has **not** been independently demonstrated from a ROM binary or a stage-specific error code.

In particular, **`0x2001` is an explicit signature rejection at an earlier path**, whereas **the later Stage-2 timeout is absence of an expected status response**. Collapsing both events into "new Amazon security blocks Stage 2" is not supported by the available evidence.

## Phase model for an actual diagnostic transcript

| Milestone (example log fragment) | What it proves | What it does not prove |
|---|---|---|
| `Successfully received DA sync` | Stage-1 DA exchanged expected protocol sync | NAND access or Stage-2 execution |
| `DRAM setup passed.` | Stage-1 acknowledged EMI initialization request | Verified DRAM stability |
| `Upload data was accepted. Jumping to stage 2...` | DA transfer acknowledged before jump-status check | Stage-2 code execution |
| `Stage was't executed. Maybe dram issue ?.` | Post-handoff status query threw an exception | Specific DRAM / NAND / security root cause |
| `Successfully uploaded stage 2` | Tool received acceptable Stage-2 boot status | Persistent root or NAND write access |
| `NAND Pagesize` and `NAND ID` | NAND-info command responded after handoff | Safe raw-NAND flashing or verified recovery |

## Reproduce a **device-free** log classification

```bash
python3 scripts/classify_mtkclient_stage2.py /path/to/previously-saved-redacted-mtkclient.log
python3 -m unittest discover -s tests -v
```

This script **only reads a local log** and prints phase flags. It never opens USB/serial ports, starts Kamakiri, jumps to Stage 2, patches a DA or modifies any hardware. Synthetic test logs verify that success acknowledgements aren't mislabeled as actual execution.

If others already have logs, the highest-value missing **non-sensitive** evidence is the exact MTKClient commit/version; DA filename and cryptographic hash/region metadata (not the proprietary DA binary); how the EMI was selected; stage-1 sync; accepted EMI-command response; type of status-read exception; and whether the host sees disconnect or a new USB device at handoff. Device serials, MEID, SOCID, secret keys and personal paths must be redacted.

**Conclusion:** No working Crumpet DA Stage-2, NAND write, root or unlock has been demonstrated. The next grounded step is **offline compatibility and phase analysis**, not trial-and-error flashing or speculative exploit payloads.

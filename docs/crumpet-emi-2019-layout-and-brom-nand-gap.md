# Crumpet Raw NAND: BROM EMI auto-discovery and 2019 Preloader extraction bug

**Verified 2026-10-09**. Exact device **Echo Dot 3rd Gen Refresh / C78MP8 / `crumpet` / MT8167/MT8516 with raw NAND**. This is not `donut`. **Upstream code pinned to** [bkerler/mtkclient `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9). Sources: [XFLASH host code](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L1097-L1165), [`DAconfig.m_extract_emi()`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/daconfig.py#L120-L164), verified original 2019 archive and 2021 / Nov-2025 Amazon Crumpet OTA Preloader partitions.

**Scope:** static Python/AST review, **isolated execution of only the original pure-data `DAconfig.m_extract_emi()` function** (no MTKClient imports/USB), and independent offline byte-layout tests. No USB commands, DA upload, exploit, firmware writes or device access. No proprietary images or EMI bytes are redistributed in this repository.

## 1. New direct source finding: generic BROM EMI auto-discovery ignores raw-NAND chip IDs

During XFLASH `upload_da()`:

- If Stage 1 says `GET_CONNECTION_AGENT == b"brom"` and `self.daconfig.emi is None`, MTKClient invokes `get_emmc_info(False)` and perhaps `get_ufs_info()`, then loops over its `Loader/Preloader/` files.
- A prospective Preloader is selected by **`if emmc_info.cid[:8] in data:`**, not by the Crumpet **NAND ID `C2 DC 90 A2 57 03`**, board identity, Preloader SHA-256 or a raw-NAND chip profile.
- That branch contains **no `get_nand_info()`**. If no candidate is found, it warns **`No preloader given. Operation may fail due to missing dram setup.`** and **continues** to the Stage-2 launch. An optional eMMC information structure may still be returned on a NAND board; a spurious CID match therefore also cannot be excluded.
- With an explicitly obtained, correctly parsed `self.daconfig.emi`, the BROM branch instead calls `send_emi(self.daconfig.emi)` and **returns False if the send fails**. The `preloader` connection-agent branch does not perform that extra explicit EMI initialization. That does not establish that all of Crumpet's installed Preloader DRAM setup is healthy.
- Before both branches, `upload_da1()` calls `sync()`, `setup_env()`, and `setup_hw_init()` **without checking their individual return values**; this [was previously validated separately](../scripts/audit_xflash_mode_flow.py). A later DA2 timeout need not be caused by a DA2-specific exception.

**Implication:** Reports of successful Crumpet BROM/Kamakiri/DA1 traffic do not demonstrate that DA1 received a compatible DRAM initialization. This is a concrete host-code limitation, but it is **not proof** of the actual runtime failure mechanism on any reported Crumpet.

## 2. Stronger result: all three verified Crumpet images contain **exactly the same valid 400-byte EMI block**

We compared the 2019 public NAND excerpt and Amazon's exact official 2021 and 2025 `brhgptpl_0` partitions, the latter SHA-256 verified against their corresponding `CrAU` OTA manifests. Rather than assume the GFH signed-body length identifies the correct trailer, we located the unique internal **`MTK_BLOADER_INFO_v28`** marker and required that **exactly 400 bytes later** the stored size footer equals 400 (`0x190`). We hashed only those 400 embedded bytes; no block was committed.

| SHA-256-pinned Crumpet Preloader | File offset of 400-byte embedded EMI | SHA-256 of embedded 400 bytes | Stored 400-byte size footer |
|---|---:|---|---|
| Public [2019 archive](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin), `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637` | `0x21590` | `c2a394668216e8bc20959bef29aee38002854a0b38444f6fcd9877fd5d548120` | `0x190` |
| Official 2021, `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` | `0x2C5D8` | **identical** | `0x190` |
| Official Nov 2025, `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a` | `0x2C7CC` | **identical** | `0x190` |

The genuine **2019 EMI is therefore not absent or obviously a different board-specific DRAM profile**. This aligns with our earlier observation that further 2021/2022/2024/2025 Crumpet official OTA images repeat the same short EMI record. It does **not** prove all live Crumpet RAM chips, DRAM initialization states or preloader/DA1 handoffs are interchangeable.

## 3. Reproduced failure in MTKClient's actual 2019 data-extraction logic

We extracted the **original Python AST node `DAconfig.m_extract_emi()`** from the pinned upstream source and executed *that one method only* on the hash-verified images with a minimal fabricated class containing just the XFLASH-mode flag. No MTKClient application or hardware code was imported or executed. We independently reproduced the result using the [new read-only audit tool](../scripts/audit_crumpet_emi_fallback.py).

| Input | Last word of upstream GFH-trimmed body | **Actual** `m_extract_emi()` return value | Valid expected 400-byte block? |
|---|---|---|---|
| Public 2019 Crumpet | **`0xFFFFFFFF`** (FF padding) | `emiver=28`, **37,152 bytes**, SHA-256 `a434ab40461189a492c8f0b56790f07a7edc5dee98b4e746d65a362192cb51b2` | **No**. Result starts with `01 00 00 00 ...` instead of `MTK_BLOADER_INFO_v28` |
| Official 2021 | `0x00000190` | `emiver=28`, **400 bytes**, SHA-256 `c2a394...` | **Yes** |
| Official Nov 2025 | `0x00000190` | `emiver=28`, **400 bytes**, same SHA-256 | **Yes** |

**Root cause in the host extractor (as a source/data fact):**

1. `m_extract_emi()` seeks an `MMM\x01\x38...` GFH FILE_INFO header and truncates data using its declared `mlen - siglen`.
2. It interprets the **last four bytes of that truncated slice** as `dramsize`. This happens to equal **`0x190`** in the official 2021/2025 images but equals **`0xFFFFFFFF`** in the archived 2019 wrapper because the reported GFH layout lands the parse at FF padding **after** the real embedded 400-byte EMI.
3. There is no upper bound or exact footer-correlation check for this value. Slicing with `data[-0xFFFFFFFF-4:-4]` on the short 2019 Python `bytes` object silently includes almost the **entire signed-body slice** (apart from the last four FF bytes).
4. `MTK_BLOADER_INFO_v28` and `MTK_BIN` occur *inside* that accidentally oversized content. The parser therefore still detects **version 28**, then returns all bytes **after `MTK_BIN` plus 12 bytes** through the end of that slice, yielding the spurious **37,152-byte** object.
5. The valid embedded 400-byte region exists at **`0x21590`** with the expected `0x190` footer at **`0x21720`**. The legacy function's alternate returned blob is not that region.

This identifies **a specific historical Preloader-layout compatibility failure in the host-side parser**, not a different genuine 2019 EMI record and not a validated Stage-2 exploit. In particular, the original extractor does not fail or return None for 2019: it returns a nonempty, **misleading `emiver=28` value** and a much longer blob.

## 4. What this does and does not change for Crumpet root/unlock

**Changes:** There is direct evidence for two host-side data-selection/format pitfalls that can occur *before* the Stage-2 code is ever reached:

- A Crumpet **BROM session without already available EMI** enters an automatic loader search that does not use the known raw-NAND chip ID, and may proceed without DRAM setup.
- A BROM session that derives EMI from the **unmodified 2019 public Preloader** through the generic upstream `m_extract_emi` code obtains the **wrong-sized** data block, despite the correct 400-byte block being physically present.

**Does not prove:** that either specific path actually explains the reported Crumpet timeout, that the public 2019 archive is the same Preloader used on the test hardware, that the 400-byte record alone suffices for correct DRAM timings, that DA2 has run, or that a writable/restore-safe raw-NAND transport exists. Later firmware image formats can already yield the exact 400-byte block **offline**, but there is no authorization here to transmit any EMI/DA to an irreplaceable device.

For a safe diagnostic comparison, **pre-existing, owner-authorized and privacy-redacted** logs should distinguish connection agent `brom` versus `preloader`, whether the EMI branch was entered, `Emi data accepted`/DRAM status, whether `setup_env`/hardware setup was acknowledged, and the exact first 12-byte DA2 status response. As before, **no NAND or boot partition writes** without fully verified recovery.

## 5. Reproduce using immutable original-source and locally pinned images

```bash
python3 scripts/audit_crumpet_emi_fallback.py \
  /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py \
  /path/to/verified/public-2019-brhgptpl_0.bin \
  /path/to/verified/official-2021-brhgptpl_0.bin \
  /path/to/verified/official-2025-brhgptpl_0.bin

python3 -m unittest discover -s tests -q
```

The checker accepts **only the three known SHA-256 images**, prints **hashes, offsets and lengths**, and does **not** output, export or upload the copyrighted EMI bytes. Its ten [manufactured-source/GFH regression tests](../tests/test_audit_crumpet_emi_fallback.py) cover both valid 400-byte and legacy FF-padded trailers, old-parser false success, altered footer, unknown image rejection, and the missing raw-NAND-ID discovery condition. A source-level structural change in MTKClient is flagged for re-review.

**Practical status unchanged:** no working root, no proven bootloader unlock, no successful DA2 confirmation and no safe NAND-restoration procedure for Crumpet. This work narrows a reproducible **host-side preparation bug** but does not assert that a real device is ready to be modified.

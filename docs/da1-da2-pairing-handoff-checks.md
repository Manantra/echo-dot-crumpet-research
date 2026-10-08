# MT8167 Crumpet: Stage-1/Stage-2 pairing and hidden DA1 setup failures

**Research date:** 2026-10-08. **Evidence:** current upstream [MTKClient source at commit `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9), the two bundled 0x8167 DA binary pairs examined **offline**, [Pexar MT8167 issue #9](https://github.com/bkerler/mtkclient/issues/9), and published [Crumpet BROM experiences](https://github.com/R0rt1z2/amonet-koboreru/issues/2). No Download Agent was executed on hardware, no USB device accessed, and no flash or security state modified.

This report extends the [MT8167 DA2 binary/EMI comparison](da2-binary-emi-compatibility.md), [Stage-2 XFLASH status protocol analysis](da2-handoff-status-memory.md), and [DA hardware-version matching study](mt8167-hw-revision-da-selection.md).

## 1. Both bundled DA1 programs contain the SHA-1 digest of their **own** DA2

The two downloaded MTKClient DA containers are binary-distinct. Both advertise HW `0x8167` and consist of DA1, DA2 and an ancillary region. After removing the **0x100-byte declared signature tail** from each DA2 region, the actual SHA-1 of DA2's executable payload is present byte-for-byte inside the corresponding DA1:

| DA1 container | DA2 candidate | Full DA2-body SHA-1 present in DA1? | DA1-body offset |
|---|---|---|---|
| `MTK_DA_V5.bin` | `MTK_DA_V5.bin` | **Yes** | `0x1A134` |
| `MTK_AllInOne_DA_mt6590.bin` | `MTK_AllInOne_DA_mt6590.bin` | **Yes** | `0x21A58` |
| V5 DA1 | AllInOne DA2 | **No** | — |
| AllInOne DA1 | V5 DA2 | **No** | — |

The two SHA-1 values are:

- V5 DA2 (signature excluded): `52e8ad359728f802c0ef9d9e556ed6d94da11abc`
- AllInOne DA2 (signature excluded): `9907862b518dffe1dba9b9073ff9e2c9bce263ca`

Neither cross-container DA1 embeds the complete MD5, SHA-1 or SHA-256 of the alternative DA2 under our exact-body check.

The linkage is consistent with [MTKClient's `compute_hash_pos()` and `fix_hash()` implementation](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/mtk_daloader.py#L83-L155), which detects a DA2 hash in DA1 and updates the reference when an authorized mode patches DA1/DA2.

**Inference and important limit:** The existence of the correct SHA-1 in DA1 is direct evidence of intended pairing. It is **not proof** that DA1 performs that exact hash verification on Crumpet, nor that replacing a hash will bypass hardware signing or make a nonstandard DA safe. Combining DA1 from one bundle with DA2 from the other **without** matching the digest breaks the published pairing metadata.

## 2. BROM and Preloader paths in upstream MTKClient differ *before* the DA2 upload

Source: [`xflash_lib.py` lines 952–1000, 1097–1198](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L952-L1198).

1. Both modes first load DA1, jump to its initial entry, and establish the initial XFLASH handshake.
2. **BROM/DA1 connection agent:** MTKClient sends `INIT_EXT_RAM` plus a separately supplied/extracted EMI blob using `send_emi()`. Where no EMI blob is provided, the automatic preloader-finding logic predominantly searches using **eMMC CID**, which does not reliably identify raw-NAND Crumpet preloaders.
3. **Preloader/DA1 connection agent:** MTKClient **skips** the separate `send_emi()` call. The device's own preloader is presumed to have initialized DRAM.
4. Both routes ordinarily call the same `boot_to(stage2_load_addr, prepared_da2)` and then wait for XFLASH Stage-2 status.
5. An **additional Preloader-only Carbonara branch** is considered when there is no existing DA patch, `stock` mode is false, and `sbc` and Carbonara availability conditions are met. This is another reason not to conflate connection modes.

These are host-side code paths, **not** experiments demonstrating the hardware outcomes on Crumpet.

## 3. The prepared DA binaries also depend on patch/security conditions

In [`upload_da1()` lines 974–979](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L974-L979), MTKClient attempts DA1/DA2 modification if:

```text
patch_already_requested OR (NOT sbc_enabled AND NOT stock_mode)
```

If this condition is false, the code uses DA2 with the original declared signature trailer stripped. If it is true, `patch_da()` attempts to find the DA2 digest in DA1, modify both DAs and update the stored digest; the patch function may fail to find a digest or disable the patch flag. **Seeing a selected filename alone cannot establish the actual transmitted code bytes.**

[MTKClient issue #9](https://github.com/bkerler/mtkclient/issues/9) reports `Patching da1 ...` and `Patching da2 ...` for its **successful Pexar MT8167/eMMC/Preloader-mode Stage-2** session. The submitted Crumpet BROM/EMI summaries do **not** establish the same patch settings, DA hashes or effective binary code. The Pexar report does not include a cryptographic hash of the DA, either.

This is an important three-way confounder: **(a) BROM vs Preloader; (b) supplied EMI source; (c) effective patch/security state**. The apparent difference in success cannot currently be attributed to any one factor.

## 4. Directly reproduced MTKClient diagnostic problem: Stage-1 setup call results are unchecked

In [`upload_da1()` lines 981–994](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L981-L994), the code does:

```python
sync = self.usbread(1)
if sync != b"\xC0":
    return False

self.sync()             # result ignored
self.setup_env()        # result ignored
self.setup_hw_init()    # result ignored
res = self.xread()
if res == pack("<I", self.cmd.SYNC_SIGNAL):
    self.info("Successfully received DA sync")
    return True
```

This is a **host-code diagnostic/flow-control weakness**: failures reported as `False` by any of the three DA1 setup calls are not explicitly acted upon.

**Concrete offline reproduction against the exact upstream function:** we AST-extracted `upload_da1()` from the `cd25cf9` checkout and invoked it with **only synthetic in-memory DA metadata/file bytes and mock USB methods**. The mocks returned `False` for `sync()`, `setup_env()` and `setup_hw_init()`, but returned the expected `SYNC_SIGNAL` on the final read. The unchanged method **returned `True` and emitted `Successfully received DA sync`**. No port or real agent was involved.

**What this proves:** MTKClient's DA1 success log does *not* strictly establish success of these earlier configuration calls.

**What it does not prove:** any one of them actually failed on Crumpet, that the device could be made to fail by a particular input, or that correcting this host-side diagnostic necessarily fixes DA2 startup.

In this same function, `send_da()`, `jump_da()`, the initial `0xC0` sync byte, and final `xread()` sync result **are** directly checked; the problem is confined to the three intermediate setup-call return values.

## 5. Reproduction and safe research priorities

The new [`audit_da_pair_integrity.py`](../scripts/audit_da_pair_integrity.py) reads **local** MTKClient Loader metadata and reports embedded DA1↔DA2 MD5/SHA-1/SHA-256 matches, including cross-bundle mismatches:

```bash
python3 scripts/audit_da_pair_integrity.py /path/to/local/mtkclient/mtkclient/Loader
```

The new [`audit_xflash_mode_flow.py`](../scripts/audit_xflash_mode_flow.py) uses **Python AST only** (it neither imports nor executes upstream source code) to check exactly which mode calls `send_emi`, whether the three Stage-1 setup methods' results are unchecked, and whether both paths use the common Stage-2 upload:

```bash
python3 scripts/audit_xflash_mode_flow.py \
  /path/to/local/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py
python3 -m unittest discover -s tests -v
```

Both tools are read-only. Their included unit tests use fake DA images and manufactured Python source snippets; **no firmware included**.

### Strongest remaining discriminator

An **already captured, owner-authorized and redacted** MTKClient session showing all of the following *from the same Crumpet board* would be more useful than speculative hardware payloads: BROM/Preloader mode; DA container filename and SHA-256; actual DA patch state; EMI version and hash; whether `setup_env`/`setup_hw_init` returned success; and USB endpoint/exception state at Stage-2 status read. Existing short logs don't record all of these.

**No Crumpet root/unlock route established.** Do not mix or flash mismatched DA pairs, try generic unlock commands, write NAND, or downgrade a bootloader without a working restore procedure.

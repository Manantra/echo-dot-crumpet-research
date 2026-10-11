# Crumpet raw-NAND evidence gate: upstream decoder is lossy; compare raw captures before decoding

**Research date:** 2026-10-11. **Scope:** MT8167/MT8516 raw NAND, historically Crumpet C78MP8 with Macronix MX30LF4G28AD (131072 pages × 4352 bytes). **Method:** direct review of [gilderchuck/mtk-nand-utils](https://github.com/gilderchuck/mtk-nand-utils) original source and independent, strictly read-only synthetic-input tests. No physical Crumpet captures were acquired or compared. No code was copied from GPL/AGPL upstream. No device access or write operations.

## 1. Material source findings: why the existing decoding pipeline is NOT a raw-NAND backup

The public scripts are useful for extracting *decoded logical data*; their source does **not** establish that the output is restorable on Crumpet.

| Upstream code | Direct source observation | Consequence for recovery |
|---|---|---|
| [`mtk_nand_4k_scrambler.py`](https://github.com/gilderchuck/mtk-nand-utils/blob/main/mtk_nand_4k_scrambler.py) | Reads `4352` bytes per page; `if len(page) != 4352: break`; skips randomized XOR for an all-`FF` physical page. | An incomplete final page is ignored rather than treated as a recoverability failure. An all-FF shortcut does not independently prove that erased pages and bad-block state were decoded correctly. |
| [`mt8167_correct_ecc.py`](https://github.com/gilderchuck/mtk-nand-utils/blob/main/mt8167_correct_ecc.py) | Also stops when a read is not a full 4352B; writes only `cooked_chunk_length` data from each corrected chunk; with `--force`, prints an uncorrectable warning and nevertheless emits potentially corrupt bytes. | Output is **main-data-only**, removing spare/ECC bytes. It cannot be a drop-in physical image. A clean command exit or an output-file length alone does not certify ECC success or recovery. |

### A non-obvious layout trap

The default BCH mode (`--chunks 4`) in the original ECC script is **not implemented** as a trivial `4096 bytes of main data + trailing 256 bytes spare` slice. It parses **four interleaved subpage records**:

```text
4 * [1024 bytes payload + 8 bytes metadata/spare + 56 bytes BCH ECC]
  = 4 * 1088 = 4352 bytes per full page
```

This was independently verified with the upstream algorithm's own library parameters using `bchlib.BCH(t=32, prim_poly=17475, swap_bits=True)`: `m=14`, `t=32`, and `len(bch.encode(1032-byte test data)) == 56`.

**Important qualification:** this establishes **what this decoder expects**, **not** that every physical chip dump, NAND-controller output or board revision has that byte arrangement. A generic `first 4096 = main; last 256 = OOB` interpretation can misclassify bytes if the interleaved format applies; conversely applying interleaved offset assumptions to a contiguous-source dump is equally inappropriate. **4352 bytes per page alone does not identify or validate the correct format.**

The ECC tool also has an alternative `--chunks 8` mode; its behavior has **not** been validated against actual Crumpet media and is not silently assumed in our checker.

## 2. New independent raw-capture comparison gate

New original offline tool: [`scripts/compare_crumpet_raw_nand_captures.py`](../scripts/compare_crumpet_raw_nand_captures.py).

```bash
# For TWO previously and independently captured raw files only, never live hardware:
python3 scripts/compare_crumpet_raw_nand_captures.py capture_a.bin capture_b.bin

# Explicitly use a particular assumed page layout only if source method proves it:
python3 scripts/compare_crumpet_raw_nand_captures.py capture_a.bin capture_b.bin \
  --layout interleaved-four

# Laboratory excerpt only (does NOT qualify as a full backup):
python3 scripts/compare_crumpet_raw_nand_captures.py small_a.bin small_b.bin \
  --allow-partial
```

**Fail-closed input checks:** accepts only two *distinct*, already-existing **regular files** (no symlinks, block devices, or FIFOs); rejects same inode/hardlink, empty files, over-capacity size, unequal lengths, and a final incomplete 4352B page. **By default requires exactly 570425344 bytes** per file (historical geometry; not a universal modern C78MP8 guarantee). Explicit `--allow-partial` never reports full scope. Input file mutation during a run is detected by a final stat check; no OS-level read snapshot is guaranteed.

**Streaming comparison:** independently SHA-256-hashes both captures, compares every full raw page, reports mismatch count, distinct 64-page erase-block count, and a limited page-index sample. It does **not** output NAND contents, dump chunks, keys, or device identifiers. Memory use is bounded to roughly a physical page of each input plus small summary structures.

**Opt-in format assumptions:** `--layout opaque` (default) only compares whole pages; `interleaved-four` separates the four assumed `1024+64` chunk regions for reporting **byte differences**, while `contiguous` assumes `4096+256`. Neither option decodes ECC or establishes an actual OOB map. An output field explicitly says the hardware layout was **not confirmed**.

**Never claimed:** that two matching files represent independent acquisitions, correct ECC or bad blocks, a supported chip revision, a restorable layout, or an actually bootable NAND image. JSON output always has `safe_to_restore: false`, `ecc_validated: false`, `oob_structure_validated: false`, and `writeback_or_cold_boot_validated: false`.

## 3. What this changes for the root/unlock research

This is a **quality gate**, not an exploit. It addresses a practical blocker that was previously described abstractly: `decoded_image.bin` from a lossy decoding pipeline is **not** interchangeable with an unmodified raw 4096+256B readback. Preserve and independently compare the **original** main+spare captures before any PRBS/ECC transformation, and determine the byte layout using provenance and validated reference data. A complete recoverability demonstration still requires independent raw captures, correct ECC/BBT/PRBS verification, unit-private partitions preservation, and actual **writeback + cold boot** on expendable hardware.

**DA2 remains parked:** [upstream Crumpet issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2) still has BROM/Kamakiri readout reports but no same-session XFLASH status, selected DA/EMI hash, or demonstrated DA2 `SYNC`. An owner who only reached the Preloader observed `DA_IMAGE_SIG_VERIFY_FAIL (0x2001)` on that *different* access path. Avoid conflating the traces.

## 4. Reproducible offline validation

[18 original synthetic regressions](../tests/test_compare_crumpet_raw_nand_captures.py) cover exact historical size, partial and truncated input rejection, mixed page and erase-block differences, the `contiguous` vs `interleaved-four` disagreement, opaque default, no false recovery status, same file/hardlink/symlink refusal and premature EOF. No proprietary dump or device was used.

On research machine `hermes`, a fresh checkout passed **250/250** offline unit tests on 2026-10-11. An independent one-off read-only `bchlib` initialization confirmed the upstream 4-chunk parameter result `56 ECC bytes`. These tests prove only the checker behavior, **not** a Crumpet NAND read or validated restore.

**Decision:** Keep DA2 on evidence-gated hold. The highest-value next missing ingredient is **two independent real-device main+spare captures and an independently demonstrated, safe sacrificial-board recovery**; without this, no downgrade, NAND flash, eFuse, custom LK or TEE writes are justified.

# Crumpet C78MP8 – Unlock blocker matrix and offline verification (2026-10-25)

**Target:** Amazon Echo Dot 3 Refresh (`C78MP8`, `crumpet`, MT8167/MT8516, raw NAND).  
**Source pins:** [upstream `d51af735e5b95fa2c03c0b311d5c05f0f73461d4`](https://github.com/R0rt1z2/amonet-koboreru/tree/d51af735e5b95fa2c03c0b311d5c05f0f73461d4); own research baseline [`06a5a1f`](https://github.com/Manantra/echo-dot-crumpet-research/commit/06a5a1f390e4af6a02cdfce4539eb28c7c5e85e6).

**Objective:** distinguish statically proven blockers, externally reported hardware results and the missing evidence for a persistent boot-chain unlock. NAND recoverability is a separate prerequisite, **not** another root method.

**Safety:** source and existing offline files only; no live device connections, flashing, NAND writes, DA uploads or new upstream GitHub comments/issues.

## Evidence labels

- **Verified static:** source code or checks performed against pinned material; does not imply execution on real hardware.
- **Reported:** attributed to an external researcher, not independently reproduced here.
- **Open:** primary evidence insufficient.
- **Blocked:** demonstrated obstacle under the stated source/firmware assumptions, not a proof that all possible future approaches are impossible.

## Blocker matrix: 13 evidence gates

| ID | Research path | What we can currently substantiate | Status | What would change the verdict? |
|---|---|---|---|---|
| AM-01 | Amonet custom LK handoff | In pinned Crumpet source, `usbdl_detect_key()` returns 1, `usb_cable_in()` falls back to 1, and `enter_usbdl(0)` occurs before `bldr_load_part()`. The USB handshake contains an unconditional loop. | **Blocked on normal source path** | Validated Crumpet-specific changed source and real evidence the intended LK path is reached |
| AM-02 | Amonet LK target | `LK_PART_NAME "expdb"` is absent from both CRC-verified 2019 and 2025 Crumpet GPTs (18 entries each); an undocumented firmware alias is not excluded. | **Blocked for documented GPT** | Verified actual `part_get()` mapping or credible hardware trace |
| AM-03 | Amonet patch pointers | Prior pinned preloader disassembly puts published `PART_GET_ADDR=0x20F250` inside a Thumb-2 instruction on examined builds. Live relocation/layout is not verified. | **Open; static contradictions** | Exact firmware, independently validated execution map and function boundaries |
| AM-04 | Amonet build input | Public `build.sh` requires `tees/tee_crumpet.img`, not bundled as an install-ready donor. | **Unproven build/boot route** | Authorized matching inputs and independently proven real-device boot path |
| AM-05 | New Amonet commits | [`da2070f...d51af73`](https://github.com/R0rt1z2/amonet-koboreru/compare/da2070f...d51af735e5b95fa2c03c0b311d5c05f0f73461d4) changes `devices/suez.c`, adds `include/devices/suez.h`, and modifies `tee.c`. No Crumpet source/header or main/USB changes. | **No demonstrated fix** | New Crumpet-specific code plus device-side evidence |
| DA-01 | MTKClient DA2 execution | BROM/Kamakiri access reported on some C78MP8 units; DA1 transfer acknowledgment is not an XFLASH DA2 `SYNC`. | **Open** | Existing independently checkable same-device framed DA2 `SYNC` |
| DA-02 | DA2 failure cause | Short/missing 12-byte XFLASH response can trigger a generic error; DRAM failure is not established by that message alone. | **Open; waiting on historical evidence** | Redacted same-session DA identity, EMI metadata, USB phase/timing, first ACK and subsequent status |
| DA-03 | Kamakiri false DA2 inference | `All good → Check GPT → read fail (got 0 of 512 bytes)` was identified as a different Kamakiri/eMMC code path. | **Excluded as DA2 proof** | Original program version/trace for finer attribution, not a presumed DA2 success |
| FB-01 | Fastboot unlock handler | Exact signed-LK static call graph identifies `flash:` dispatch including `unlock`, `otucert`, `otucode`. | **Verified handler only** | No extra evidence needed for handler *existence* |
| FB-02 | Usable authorized unlock | No credible obtainable credential/issuer or device-tested accepted C78MP8 production unlock. | **Open** | Authorized issue path or reproducible validated device result |
| FB-03 | Unlock string implies bypass | Actual checker and historic certification failure refute treating string presence as bypass. | **Not supported** | Version-specific demonstrated vulnerability/valid authorized process, not merely a command name |
| RC-01 | Original NAND acquisition | Joost reports ~132,000 raw files, repeated reads and decoded data; `4532` in his wording conflicts with `4096+256=4352`. | **Reported; unverified geometry** | Existing non-sensitive file lengths, provenance, hashes, ECC/OOB validation |
| RC-02 | Physical recovery | No proven NAND writeback and cold-boot restore of the same device; decoded-only files can lose OOB/ECC. | **Open; practical no-go** | Independently evidenced recoverability on expendable hardware, not experiments on a working unit |

## Offline verification run (2026-10-25)

On the authorized Linux research machine `hermes`, fresh separate local clones of our `06a5a1f` baseline and public upstream `d51af73` were inspected **without modifying upstream or interacting with any Echo device**.

**Exact commands:**

```bash
# Within the pinned research checkout, after making the optional
# Python Capstone 4 bindings available to the interpreter:
python3 -m unittest discover -s tests -q
python3 scripts/audit_amonet_crumpet_boot_flow.py ../upstream

# Within the read-only public upstream clone:
git diff --stat da2070f..d51af735e5b95fa2c03c0b311d5c05f0f73461d4
```

**Observed results:**

- `Ran 255 tests in 0.167s — OK` (exit code 0). An initial attempt without optional Capstone failed with 25 missing-import errors; this was an **environment setup problem**, not a device issue. A Debian-packaged Capstone 4 library was extracted into an isolated temporary directory, and Python was configured to find that local copy for the successful rerun. No global dependency installation was needed.
- `audit_amonet_crumpet_boot_flow.py` exit code 0, reporting `lk_partition: expdb`, `platform: mt8516`, `usb_cable_macro_defined: False`, `usb_fallback_always_true: True`, `usb_key_always_true: True`, `handshake_loop_no_source_exit: True`, `main_calls_in_expected_order: True`, `requires_missing_donor: True`, `CRUMPET DEFAULT SOURCE PATH ENTERS NONRETURNING USBDL: True`.
- `git diff --stat da2070f..d51af73` reported **3 files changed, 115 insertions**: `devices/suez.c`, `include/devices/suez.h`, `tee.c`. The common `tee.c` change is guarded by a device-specific `SEC_CRYPTO_CACHE_ADDR` macro that is **not** present in the pinned Crumpet header. That observation should not be mistaken for a runtime test.

**What was not tested:** any Amazon device, USB stage, physical NAND geometry, source-diff patch effectiveness on real hardware, firmware writes, bootloader unlock or successful recovery. No official preloader image or OTA was passed to the source-path checker in this run; the previously documented 2019/2025 GPT evidence remains the basis for AM-02.

## Evidence links and decision rule

- [Previous source/GPT boot-flow audit](amonet-crumpet-unreachable-lk-and-expdb.md) and [patch-site audit](amonet-hardcoded-patch-address-audit.md)
- [Thumb-2 target analysis](crumpet-amonet-part-get-thumb2-misalignment.md)
- [Official LK Fastboot call graph](lk-fastboot-unlock-disassembly.md)
- [Kamakiri vs XFLASH diagnostic split](crumpet-kamakiri-gpt-read-vs-mtkclient-da2-2026-10-12.md)
- [Joost's NAND evidence and source timeline](crumpet-community-evidence-update-2026-10-14.md)
- [Read-only overall strategy / stopping rules](crumpet-root-strategy-decision-2026-10-11.md)
- [Source control: upstream Crumpet header](https://github.com/R0rt1z2/amonet-koboreru/blob/d51af735e5b95fa2c03c0b311d5c05f0f73461d4/include/devices/crumpet.h), [Crumpet device source](https://github.com/R0rt1z2/amonet-koboreru/blob/d51af735e5b95fa2c03c0b311d5c05f0f73461d4/devices/crumpet.c), [boot flow](https://github.com/R0rt1z2/amonet-koboreru/blob/d51af735e5b95fa2c03c0b311d5c05f0f73461d4/main.c), [USB loop](https://github.com/R0rt1z2/amonet-koboreru/blob/d51af735e5b95fa2c03c0b311d5c05f0f73461d4/usbdl.c)

**GO:** only on new exact-C78MP8, independently reproducible evidence that closes a clearly named gate. **NO-GO:** device flashing, random DA payloads, NAND writeback or a root claim based solely on strings, synthetic tests or generic upstream commits. The developer's request for no AI-generated upstream participation must be respected.

## Addendum 2026-10-25 — independent software-only first-install route `WI-01`

The original **13 gates remain as written**. A separate optional first-install hypothesis through the stock Fire OS OOBE/OTA services was assessed with [actual SHA-256-pinned 2022/2023 system images](crumpet-fireos-oobe-ota-static-audit-2026-10-25.md). The generated `DopplerOOBE` Thrift RPC processor has 18 identical methods across both versions, with **no named firmware upload/install RPC**; the init scripts show OOBE running as `oobe`, OTA daemons as `ace_otad`, and a disabled, on-demand root `update_engine`. No direct privileged first-install capability, code execution, accepted unsigned OTA or root was validated. **Decision: PARK `WI-01`** until relevant version-specific primary evidence materializes. This does not invalidate or resolve any of the original 13 gates.

# Crumpet DA Stage-2: two separate status acknowledgments and stock DA1's SHA-1 check

**Date:** 2026-10-10. **Device scope:** Echo Dot 3 Gen Refresh **C78MP8 / crumpet**, MT8167/MT8516, raw NAND. **Upstream:** [bkerler/mtkclient `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9). **Evidence:** the original full-file SHA-256 pinned `MTK_DA_V5.bin` and `MTK_AllInOne_DA_mt6590.bin`, their executable DA1/DA2 spans, Capstone-decoded DA1 code, and original XFLASH `send_data()` / `boot_to()` Python source. **No hardware or executable DA loaded, no USB or NAND operations.**

## New evidence: "Upload data was accepted" is a **DA1 acknowledgment**, not a DA2 execution acknowledgment

The original [MTKClient `boot_to()` and `send_data()`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L272-L328) have a critical *two-stage* status progression:

1. The host submits `BOOT_TO`, reads the initial command status, sends its address/length and streams the DA2 executable through `send_data()`.
2. **`send_data()` performs an XFLASH `status()` read after streaming all bytes**. It returns **True only if this status is zero**. A nonzero error (including `0xC0070004`) causes `send_data()` to return False.
3. **Only inside the true branch** of `send_data()`, `boot_to()` prints `Upload data was accepted. Jumping to stage 2...`.
4. **Only afterwards** does the host wait and perform a **second, independent XFLASH `status()` read**. Acceptable reply values for this second status are `0x434E5953` (**ASCII `SYNC`**) or **0**. An empty/short reply can become the generic, misleading `Stage was't executed. Maybe dram issue ?.` line.
5. The **first** successful status is emitted through DA1's existing protocol callback before its indirect DA2 jump. The **second** is expected from successfully initialized DA2's framed `SYNC` routine; see [verified DA2 bootstrap and framing chain](mt8167-da2-bootstrap-r0-magic-sync.md).

**Inference supported by original host AST and DA1 opcodes:** A log line saying `Upload data was accepted` means the **host parsed a successful pre-Stage-2 data-acceptance status**. It is not evidence that DA2 reached its ARM startup or `bootstrap2` main loop. Conversely, a genuinely negative DA1 status at this first point should produce the **`Error on sending data` / `Error on boot to send_data` path**, not the familiar missing-second-ACK path.

Crucial qualification: an accepted first status does **not** cryptographically attest to unchanged bytes on device, especially when MTKClient's optional loader-patch/security-bypass paths modify DA code. It reports the DA1 protocol's success judgment as interpreted by the host. USB framing corruption or patched code may alter semantics.

## The stock DA1 binaries do compare a 20-byte SHA-1 before constructing the DA2 argument block

Our [earlier paired DA1/DA2 SHA-1 report](da1-da2-pairing-handoff-checks.md) showed the embedded per-version hashes. The new finding is **a directly confirmed instruction-level control-flow link** connecting them to the host-visible negative acknowledgment.

| SHA-1/DA1 failure site | `MTK_DA_V5.bin` | `MTK_AllInOne_DA_mt6590.bin` |
|---|---|---|
| Full original loader container SHA-256 | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` |
| Expected **20-byte SHA-1** stored in DA1 | `52e8ad359728f802c0ef9d9e556ed6d94da11abc` | `9907862b518dffe1dba9b9073ff9e2c9bce263ca` |
| DA1 SHA-1 literal-data VMA | `0x0021A134` | `0x00221A58` |
| **SHA-1 of original executable DA2** (signature tail excluded) | **Identical to DA1 reference** | **Identical to DA1 reference** |
| DA1 compares hash bytes (sample comparison site) | `0x2014A2`: `cmp r1,r2` | `0x200FBA`: `cmp r1,r2` |
| DA1 SHA-1-mismatch error literal | `0x2014C8`: `ldr r3,[pc,#...]` → `0xC0070004` | `0x200FDE`: `ldr r3,[pc,#...]` → same |
| Store error into response/status word | `0x2014CA`: `str r3,[sp,#4]` | `0x200FE0`: `str r3,[sp,#8]` |
| Call DA1 callback to transmit this status | `0x2014FA`: `blx r3` | `0x200FEE`: `blx r3` |
| Later DA1 indirect parameter handoff | `0x20154E`: `blx r8` | `0x201040`: `blx r7` |

The hash buffer is handled as a **20-byte** comparison. The pair's original DA2 hash matches exactly; replacing or cross-pairing unmodified bodies breaks this comparison unless the code or expected digest is altered. **Neither activity is a validated Crumpet recovery solution.**

### Host-side and device-side timing distinction

```text
Host          DA1                                        DA2
  |            |                                           |
  |--BOOT_TO-->|                                           |
  |--address-->|
  |--DA2 data->|-- checks received DA2 against stored SHA-1
  |<-status----|   (0 or specific error, e.g. 0xC0070004)
  |
  | [Only if status == 0:]
  | "Upload data was accepted. Jumping to stage 2..."
  |            |-- construct R0 argument; indirect BLX -> | 
  |            |                                           |-- validate magic
  |            |                                           |-- init platform + USB
  |<-----------XFLASH 12B header + 4B SYNC status----------|
  |   "Boot to succeeded" only if 2nd status == SYNC or 0
```

This diagram illustrates the intended original protocol. We **did not observe** the exact instant the original DA1 callback performs the physical indirect jump on Crumpet; an accepted first response means neither that the indirect callback actually returned to running code nor that DA2's first instruction was fetched.

## What can now be deprioritized versus what remains unknown

- **More strongly excluded as an explanation for the *specific accepted-then-timeout log*: a DA1-reported `0xC0070004` SHA-1 mismatch at the first status read**. The host would have taken a different log branch. Since MTKClient may patch DA1/DA2, however, accepted status is not proof stock cryptographic verification succeeded.
- **Separately contradicted by original instructions:** a static magic or argument-size discrepancy between the two correctly paired stock agents. DA1 constructs the correct [88B or 64B block](mt8167-da1-runtime-parameter-block-handoff.md), including magic `0xFE4A4D42`, before passing its address in `R0`.
- **Not yet distinguished on real Crumpet hardware:** failed/insufficient DRAM setup; corrupted DA1 source buffer or invalid callback target; DA2 code/relocation failure; `bootstrap2` platform/USB setup failure; or a USB endpoint reset/disconnect that masks a completed boot.
- **Not changed by this finding:** stock V5 DA2 contains an exact [historical MX30LF4G28AD NAND ID profile](mtkclient-stage2-nand-profile-transport.md), but the NAND controller cannot be queried until DA2 and transport work; safe raw NAND ECC/OOB readback and restore are not established.

The independent [MTKClient MT6739 report #26](https://github.com/bkerler/mtkclient/issues/26) and [MT6761 report #257](https://github.com/bkerler/mtkclient/issues/257) show **the same accepted-then-no-Stage2-reply symptom with explicit DRAM setup passed** on different hardware. Those anecdotes **do not prove the Crumpet cause**, but demonstrate why a one-line "DRAM issue" label is not diagnostic.

## Reproduce completely offline

New [`scripts/audit_da1_stage2_sha1_ack.py`](../scripts/audit_da1_stage2_sha1_ack.py) cross-validates two full-file SHA-256-pinned DA1/DA2 pairs, computes each original executable DA2 SHA-1, decodes the DA1 compare/mismatch status/return callback/handoff instructions, and analyzes original Python source **using AST** for the first status==0 gate and the separate second status after printing the acceptance line.

```bash
python3 scripts/audit_da1_stage2_sha1_ack.py \
  /path/to/pinned/mtkclient/mtkclient/Loader \
  /path/to/pinned/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py

python3 -m unittest discover -s tests -q
```

The [ten new synthetic source+SHA1 regression tests](../tests/test_audit_da1_stage2_sha1_ack.py) require correct digest length, detect modified DA2, fail on an unknown DA container, and verify a strictly positive first acknowledgment and later independent Stage-2 read. They neither include whole firmware binaries nor contact devices.

**Practical impact:** Existing redacted Crumpet logs that reach `Upload data was accepted...` should be investigated as a **post-DA1-data-ack problem**, not a confirmed DA1 hash rejection, successful DA2 launch, or a failed NAND controller lookup.

**Final status:** No working root/bootloader unlock, confirmed DA2 execution or recoverable NAND flash procedure has been demonstrated for Crumpet C78MP8.

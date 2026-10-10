# Crumpet DA Stage 2: actual DA1 construction and R0 handoff, not just a DA2 magic check

**Research date:** 2026-10-10. **Target:** Amazon Echo Dot 3rd Gen Refresh **C78MP8 / crumpet**, MT8167/MT8516 and **raw NAND**. **Source:** [bkerler/mtkclient commit `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9), exact original SHA-256-pinned DA1/DA2 pairs in its stock `Loader` directory. **Method:** original Thumb/ARM disassembly, cross-reference of literal pools, RAM pointers, data transfers and register handoff, verified with a new offline checker and synthetic unit tests. **No physical device, USB, DA launch, NAND writes or vendor binary redistribution.**

## Main result: the original DA1 **constructs** the DA2 magic and complete parameter block

Earlier [DA2-only disassembly](mt8167-da2-bootstrap-r0-magic-sync.md) identified `bootstrap2`'s fatal `0xFE4A4D42` magic gate and a valid XFLASH-framed `SYNC` notification after successful startup. We now followed the *other side* of that ABI to the **actual DA1 instructions that assemble the buffer and pass it in `R0`**.

| Data and instruction provenance | DA V5 | DA AllInOne alternative |
|---|---|---|
| Original container SHA-256 | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` |
| DA1 load base | `0x00200000` | `0x00200000` |
| **DA1 runtime parameter buffer** | **`0x00239018`** | **`0x00222A70`** |
| DA1 loads static magic literal `0xFE4A4D42` | `0x201512` | `0x201008` |
| DA1 writes magic into **first word** of buffer | **`0x20151A`**: `str r3,[r6]` | **`0x201010`**: `str.w r3,[lr]` |
| Buffer word `+4`: bit 1 of another runtime control word | `ubfx r3,r3,#1,#1`, then `str r3,[r6,#4]` at `0x201524` | same extraction, then `str.w r3,[lr,#4]` at `0x20101C` |
| First 24B runtime source | `0x00239150` | `0x00222B88` |
| First copy into buffer **offset +8** | **16+8B** `LDM/STM` | **16+8B** `LDM/STM` |
| Second runtime source | `0x002393B8` | `0x00222C50` |
| Second copy into buffer **offset +32** | **16+16+16+8 = 56B** | **16+16 = 32B** |
| **Total param block** | **8 + 24 + 56 = 88B** (`0x58`) | **8 + 24 + 32 = 64B** (`0x40`) |
| Move buffer pointer into `R0` | **`0x20154C`**: `mov r0,r6` | **`0x20103E`**: `mov r0,lr` |
| Indirect handoff call | **`0x20154E`**: `blx r8` | **`0x201040`**: `blx r7` |
| DA2's subsequently verified copy size | **88B** into `0x400638D0` | **64B** into `0x4003F430` |
| DA2 first-word magic check | **`0xFE4A4D42`** | **`0xFE4A4D42`** |

**Register handoff:** Both DA1 functions obtain the *indirect call target* earlier from a stack slot **`[sp,#0x10]`**, populated through a preceding callback. For V5, `ldr.w r8,[sp,#0x10]` at `0x201438`; for the alternative, `ldr r7,[sp,#0x10]` at `0x200F78`. Both have a prior indirect read/callback (`ldr r3,[r7]` then `blx r3` at V5 `0x201430/0x201432`, or `ldr r3,[r6]` then `blx r3` at `0x200F56/0x200F58`). The read callback's actual return data is **not captured** in any published Crumpet runtime log. We therefore do not claim the resulting actual target address or the runtime value of `R0` is known, beyond the original software contract.

### Selected original Thumb instructions, V5

```asm
0x201510  ldr   r6,[pc,#0x7c]   ; 0x239018 (DA1 runtime param buffer)
0x201512  ldr   r3,[pc,#0x80]   ; 0xFE4A4D42
0x201514  ldr   r5,[pc,#0x80]   ; 0x239150 (first runtime source)
0x201516  add.w r4,r6,#8
0x20151A  str   r3,[r6]         ; param word +0 = known magic
0x20151C  ldr   r3,[pc,#0x7c]   ; 0x239308, another runtime source
0x20151E  ldr   r3,[r3,#8]
0x201520  ubfx  r3,r3,#1,#1
0x201524  str   r3,[r6,#4]     ; param word +4 = extracted bit
0x201526  ldm   r5!,{r0-r3}    ; source 0x239150
0x201528  stm   r4!,{r0-r3}
0x20152A  ldm.w r5,{r0,r1}
0x201530  stm.w r4,{r0,r1}     ; first 24B copied to destination +8
0x201534  add.w r4,r6,#0x20
0x201538  ldm   r5!,{r0-r3}    ; source 0x2393b8
...
0x201548  stm.w r4,{r0,r1}     ; last eight bytes of second 56B
0x20154C  mov   r0,r6           ; **DA2 input R0 = param-block pointer**
0x20154E  blx   r8              ; dynamic target from earlier callback
```

The second original DA differs in addresses and transfer counts but follows the **same logical construction**. This relationship was established by **actual Thumb instruction decoding and PC-relative literal resolution**, not by scanning only for the magic constant.

## Follow-up (2026-10-10): DA1 integrity acknowledgment is distinct from DA2 boot `SYNC`

The [opcode- and host-AST-verified DA1 SHA-1/status report](da1-sha1-status-vs-da2-sync-ack.md) now shows that DA1 compares a 20-byte digest against an embedded SHA-1 for its own DA2 and emits `0xC0070004` on mismatch. Original `send_data()` returns True **only when the first framed DA1 status is 0**, so `Upload data was accepted...` does **not** report an *already returned* DA1 hash rejection. **It also does NOT confirm DA2 executed:** host awaits a separate `SYNC` frame after the indirect jump. The jump/copy register ABI described here is still unobserved on physical Crumpet RAM; the artifact is offline-only.

## Follow-up (2026-10-11): the second DA1 source block is actually mutable

A new [direct static xref and field-store audit](crumpet-da1-mutable-state-and-october-2026-unlock-status.md) verifies that DA1's **56B V5** second source (`0x2393B8`) has **16 literal address occurrences and six actual `STR` sites within the transferred range**, while the **32B AllInOne** second source (`0x222C50`) has ten address occurrences and four store sites. This proves the transferred structure includes **live state**, not just immutable firmware constants. The dynamic values and their relevance to the real Crumpet timeout are **not measured**; no specific field has been conclusively identified as a USB endpoint, DRAM status or chip ID. The previously verified static magic/header ABI remains correct for each original matched pair.

## 2. What this corrects about the suspected bad-magic Stage-2 hang

The previous analysis found a **real possible DA2 error condition**: if the copied parameter block's first word is **not** `0xFE4A4D42`, the `bootstrap2` thread deliberately spins forever **before** sending `SYNC`.

**Now the key qualification is stronger:** within each original matched pair, DA1 **writes exactly that required magic in executable code**, then passes its constructed buffer pointer. Both exact transfer sizes independently agree with DA2's copy sizes. This makes a **static DA1/DA2 format discrepancy unlikely for either unmodified matched pair**. A magic mismatch on an actual device would require an additional deviation—such as an invalid runtime buffer/source, memory corruption, wrong indirect transfer, a mixed or patched agent, or an earlier DA1 initialization failure.

We have **not established which runtime deviation, if any, occurs on Crumpet**. In particular the source RAM regions `0x239150/0x2393B8` and `0x222B88/0x222C50` and the stack-derived indirect call targets are **dynamic**, and their actual contents are not implied by the DA1 executable bytes.

This is an **elimination/priority update**, not a root exploit: prioritize checking confirmed EMI/DRAM initialization and what happened at the DA1→DA2 indirect call or USB transition, rather than changing the already matching `0xFE4A4D42` constant.

## 3. Remaining independent Crumpet blockers

- [Actual 2019 EMI parser false-success and raw-NAND BROM auto-detection gap](crumpet-emi-2019-layout-and-brom-nand-gap.md): original MTKClient parser mis-extracts **37,152 bytes** from the public 2019 Preloader despite its correct embedded **400-byte** EMI; missing-EMI BROM search uses eMMC CID, not NAND ID. Those defects are upstream of the stage discussed here.
- [V5 DA2 exact historical Macronix NAND profile](mtkclient-stage2-nand-profile-transport.md) proves that stock V5 contains the historical `MX30LF4G28AD` chip ID/4096+256 geometry, but **not** that DA2 or its NAND controller runs on Crumpet.
- [Crumpet Amonet source/control-flow and pointer incompatibilities](amonet-crumpet-unreachable-lk-and-expdb.md) remain independent blockers after DA2.
- No verified full 512MiB NAND+OOB and ECC/bad-block-aware recovery image, persistent root or bootloader unlock has been independently demonstrated.

## 4. Reproduce safely (no device access)

```bash
python3 scripts/audit_da1_runtime_handoff.py \
  /path/to/verified/mtkclient/mtkclient/Loader
python3 -m unittest discover -s tests -q
```

The [new opcode-validated, pinned-binary auditor](../scripts/audit_da1_runtime_handoff.py) requires exact original DA container SHA-256, traces Thumb literal loads, writes, 16-/32-bit LDM+STM copies, R0 handoff, the **stack-sourced indirect call address**, and invokes the pre-existing **DA2 instruction-level auditor** for independent expected magic and size agreement. It fails closed on changed binaries or unfamiliar code.

Ten new [manufactured-code regression tests](../tests/test_audit_da1_runtime_handoff.py) cover PC-relative literal interpretation, transfer register-list sizes, mismatched read/write totals, Thumb `mov`/indirect `blx`, expected paired block lengths and unknown originals. No proprietary agents or modified firmware are included.

**Bottom line:** A genuine *matching* DA1/DA2 pair has a **verified self-consistent runtime ABI**. The observed Crumpet `Stage was't executed` log still does **not** tell us whether the live parameter block was intact, DA2 began, or USB was lost. Solving that requires independent same-device observational evidence, not a blind RAM or raw-NAND write.

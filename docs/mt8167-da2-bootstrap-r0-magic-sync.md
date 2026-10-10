# MT8167 Crumpet DA2 boot contract: the R0 parameter handoff, fatal magic gate, and framed SYNC

**2026-10-09** · Device: Echo Dot 3 Refresh C78MP8 / **Crumpet**, MT8167/MT8516, raw NAND. **Source:** [bkerler/mtkclient commit `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9) and both bundled original `HW 0x8167` DA loader pairs. **Method:** binary SHA-256 validation, ARM32/Thumb-2 disassembly using Capstone 4.0.2, data-pointer and control-flow cross-reference. **No device, USB, DA execution, vendor code redistribution or flash writes.**

## Executive breakthrough: a new, fully decoded Stage-2 failure path *before NAND*

The two stock agents share a previously unidentified **DA1→DA2 runtime-argument contract**, and **DA2 does not notify the host that it is ready until it has passed a fatal parameter-validation gate and initialized its command dispatcher**.

Both DA1 executable payloads contain the little-endian argument magic **`0xFE4A4D42`** exactly once. Both DA2 initial ARM prologues **store the incoming CPU `R0` argument pointer into writable program address `0x40000020`**:

```asm
0x40000024  ldr r6, [pc, #0xd0]  ; literal at 0x400000FC = 0x40000020
0x40000028  str r0, [r6]         ; SAVE INCOMING R0
...
0x400000F4  blx ...              ; switch to DA-specific Thumb kmain
0x400000F8  b   0x400000F8      ; if kmain ever returns, spin indefinitely
```

The **stored** DA2 file has **zero at `0x40000020`**; it is filled by the live DA2 entry point, not the host's `send_data()` or a permanently embedded pointer. The Thumb `kmain` then loads the value at `0x40000020` as a **source pointer**, copies a DA-specific parameter structure into a BSS buffer using a **genuine ARM-state memcpy/memmove-style routine**, and schedules a `bootstrap2` thread. This inference is supported by disassembly of the ARM helper (registers `r0`=destination, `r1`=source, `r2`=length; `LDM r1!`, `STM r0!` and byte-tail instructions), **not** solely by function-name guessing.

`bootstrap2` checks the **first 32-bit word of the copied structure** against `0xFE4A4D42`. The actual Thumb instructions are **`ldr r2,[r4]; cmp r2,r3; beq <continue>`**. If the comparison fails, the thread optionally prints `bootstrap2 argument magic error. halt.` and reaches a literal **`b .` / self-loop**. This happens **before `platform_init`, `dagent_register_commands`, or the ready-status notification**.

**Critical nuance:** This demonstrates a definite software *failure path* capable of explaining "no Stage-2 reply" with an already-running DA2; there is **no Crumpet RAM/register trace** to show that the magic was actually wrong on real hardware. A dead source pointer could also cause an earlier memory access fault; memory validity and handoff ABI remain hardware-dependent.

## 1. Precise side-by-side execution map

| Verified feature | `MTK_DA_V5.bin` | `MTK_AllInOne_DA_mt6590.bin` |
|---|---|---|
| DA container SHA-256 | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` |
| DA1 offset with `0xFE4A4D42` | `0x1594` | `0x1078` |
| DA2 stored argument-pointer slot | `0x40000020` (zero in file) | same |
| Initial `BLX` into Thumb `kmain` | `0x40000C3C` | `0x40000A48` |
| `kmain` copies external arg structure | **88 bytes, `0x58`** | **64 bytes, `0x40`** |
| Destination buffer in DA2 BSS | `0x400638D0` | `0x4003F430` |
| ARM-state copy helper | `0x4000AC10` | `0x40007718` |
| `bootstrap2` thread entry | `0x40001D74` | `0x40001428` |
| At `bootstrap2`, read source + compare magic | `0x40001D86`–`0x40001D8E` | `0x40001438`–`0x40001440` |
| **Magic mismatch: infinite self-loop** | **`0x40001D9E`** | **`0x40001450`** |
| Initialize platform | call at `0x40001E60` | call at `0x400014BE` |
| Register DA protocol commands | call at `0x40001E80` | call at `0x400014DE` |
| Ready notification called from `bootstrap2` | call `0x40001E92` → **`0x40006E88`** | call `0x400014F0` → **`0x40004BE0`** |
| After notification: enter command processing | `0x40006C68` | `0x40004A34` |

Previously decoded BSS intervals are **`[0x400559A0,0x4006A520)`** for V5 and **`[0x400315A0,0x400456E0)`** for the alternate. Both copied parameter structures lie inside their respective zero-initialized DA2 BSS. The fact that the copies have **different lengths** also shows that the two DA1/DA2 formats should **not** be assumed interchangeable. Each DA1 independently contains the SHA-1 of its own DA2 body, as recorded in [our DA-pair integrity report](da1-da2-pairing-handoff-checks.md).

The log strings embedded in both bootstrap functions (not proof that they were actually printed by Crumpet) include:

```text
***8.Enter bootstrap2***
bootstrap2 argument magic error. halt.
DRAM address: 0x%llx, size: 0x%llx
***9.platform_init***
***9.platform_init pass***
***10.dagent_register_commands.
***11.notify host DA is ready to execute commands.
```

These strings are referenced by **actual Thumb PC-relative literal-load instructions in their associated functions**. Notably, the debug strings have verbosity checks; the **absence of one in an ordinary log cannot prove that the step did not happen**.

## 2. What DA2 actually sends to the host: **valid framed `SYNC`**, not a bare four-byte packet

The ready-notification routines at **`0x40006E88`** (V5) and **`0x40004BE0`** (alternative) both:

1. Load **`0x434E5953`** (little-endian bytes `53 59 4E 43` = ASCII `SYNC`).
2. Place these **four bytes** into a stack buffer.
3. Call a transport function using a stored function-pointer table, with `r0` = buffer pointer and `r1` = 4.
4. Dispatch into a framing helper that sends the **12-byte XFLASH packet header before the four-byte payload**.

The actual function-pointer tables have matching runtime addresses:

- **V5**: table **`0x40053540`**, slot `+4` = **`0x4000A9B9`** (Thumb), whose statistics wrapper calls frame-building routine **`0x40006DEC`**. Its literal at `0x40006E30` is **`0xFEEEEEEF`**, and code places data type **1** and payload size **4** into the header. The I/O callback is then called with 12 bytes, followed by the payload.
- **Alternative**: table **`0x40030850`**, slot `+4` = **`0x40004B59`** (Thumb). That helper itself builds magic **`0xFEEEEEEF`** via `movw r3,#0xeeef` plus `movt r3,#0xfeee`, then transmits the 12-byte header and the four-byte payload.

The resulting *intended* status frame is:

```text
EF EE EE FE   01 00 00 00   04 00 00 00   53 59 4E 43
  XFLASH      datatype = 1   length = 4       "SYNC"
```

This **agrees** with the original [MTKClient `status()` / `boot_to()`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L138-L158) framing and accepted `0x434E5953` success code. **We should not blame an intrinsic "bare SYNC instead of XFLASH header" mismatch on either of these stock DA2 versions.** A runtime USB transport failure or a partial write is a separate matter and remains unobserved.

The subsequent calls at `0x40001E96` or `0x400014F4` enter per-version protocol/command processing. Whether those loops ever run on a particular Crumpet unit has not been established.

## Addendum (2026-10-09): actual BROM EMI selection and old Preloader parser bug

[New SHA-pinned original method + firmware study](crumpet-emi-2019-layout-and-brom-nand-gap.md) identifies **two earlier host preparation traps**: XFLASH BROM auto-discovery searches by eMMC CID instead of Crumpet raw-NAND ID when no EMI is supplied; the public 2019 Preloader's GFH-trimmed last word is `0xffffffff`, which makes upstream `DAconfig.m_extract_emi()` return an **incorrect 37152-byte object with `emiver=28`** even though a valid **400-byte identical Crumpet v28 EMI record** sits in the file. Modern 2021/2025 Preloaders return the correct same 400B offline. This can explain **incompatible Stage1 DRAM preparation hypotheses**, not a proven runtime Crumpet Stage2 stall. The DA2 runtime parameter magic check remains a distinct, later possible failure mechanism.

## Critical follow-up (2026-10-10): DA1 builds the required magic structure itself

The [new byte-and-opcode-validated **DA1-side construction analysis**](mt8167-da1-runtime-parameter-block-handoff.md) proves `0xFE4A4D42` is **actively written by the original DA1 to its runtime argument buffer**, rather than merely present somewhere in a binary. The two DA1 binaries build exact **88B and 64B** structures (8-byte magic/flag header, 24-byte first data copy, and 56/32-byte second data copy) and explicitly pass the buffer address in `R0` via an indirect `BLX`. Their matched DA2 copies require exactly those lengths and the same magic. This **weakens the earlier suspicion that the fatal `bootstrap2` magic branch is commonly reached in normal paired operation**. It remains a possible path only if *live* memory, source data, indirect jump or agent integrity is wrong. No Crumpet RAM-register evidence currently selects this condition. Other conditions (EMI/DDR, early USB switch, DA2 platform_init) remain independent possibilities.

## 3. Stronger diagnostic discrimination for an already-captured Crumpet session

The combination of this binary study and the prior [host transport audit](mtkclient-stage2-nand-profile-transport.md) produces **four distinct possibilities**, none yet selected by actual Crumpet registers or UART timing:

| Where execution stalls | Expected side effects | What available public logs prove |
|---|---|---|
| Before DA2 ARM entry or invalid code/DRAM mapping | No DA2 runtime parameter access or status | **Cannot distinguish** |
| DA2 entered, but saved incoming R0 is invalid | Fault during `kmain` external-parameter copy | **Cannot distinguish** |
| Copied first argument word is **not `0xFE4A4D42`** | `bootstrap2` executes deliberate endless branch before host notification; error text **might** appear at sufficient log level | **Cannot distinguish** |
| Magic valid, but platform/command/USB init fails | Missing, partial or lost framed `SYNC` | **Cannot distinguish** |
| Framed `SYNC` physically emitted, host endpoint stale/disconnected | Device may have run DA2, but host's `usbread(12)` reports short/empty | **No matching real Crumpet packet capture** |

The important new *negative*: **The DA2 code knows how to produce the correct XFLASH status header and the V5 DA2 already contains an exact table entry for the historical Crumpet Macronix NAND chip**. Generic suggestions to swap in an unrelated DA or treat every timeout as a bad NAND driver are no longer evidence-based.

**High-value next action, strictly observational:** collect/compare **already-authorized pre-existing logs** or UART captures and check whether `bootstrap2 argument magic error. halt.`, `***9.platform_init***`, `***10.dagent_register_commands.` and `***11.notify host DA is ready...` were ever observed with actual timestamps; correlate with host USB enumeration and the *first* XFLASH 12-byte response. Missing log strings alone mean little because of verbosity gating. A targeted RAM-register trace, if one is independently and safely available, would be decisive, but **no speculative BROM/DA code upload is proposed here**.

## 4. Reproduce with pinned binaries and manufactured-code tests

New original read-only [`audit_da2_bootstrap_contract.py`](../scripts/audit_da2_bootstrap_contract.py) verifies these links **on both full-file SHA-pinned, original MTKClient containers**:

- Identifies the magic in **each DA1**, exact ARM `R0` save + slot literal + `BLX`, Thumb `kmain` parameter copy, cross-ISA ARM copy helper, thread callback pointer, magic compare and self-loop, ready-callback, actual I/O function-pointer table, XFLASH framing code and eventual command loop.
- **Refuses unrecognized hashes**, altered opcodes, unexpected memory addresses, missing mandatory paths, or missing Capstone.
- Does not patch agents, invoke MTKClient, run ARM code, access USB/NAND or export any original binaries.

```bash
python3 scripts/audit_da2_bootstrap_contract.py \
  /path/to/mtkclient/mtkclient/Loader

python3 -m unittest discover -s tests -q
```

Thirteen new unit tests use **manufactured minimal ARM/Thumb instruction snippets and synthetic parameters only**, including changed R0 target, invalid branch, incorrect stored pointer, unknown file SHA-256 and altered Thumb literal. The source and synthetic tests contain **no copyrighted Amazon/MediaTek firmware body**.

**Conclusion:** We now have a **concrete DA2 software failure mechanism consistent with a missing `SYNC`** and a confirmed *correct* XFLASH status format. It is **not proof of a Crumpet hardware failure mechanism**, let alone a functioning root/unlock. Successful DA2 and a reliable bad-block-aware raw-NAND read/restore path remain missing.

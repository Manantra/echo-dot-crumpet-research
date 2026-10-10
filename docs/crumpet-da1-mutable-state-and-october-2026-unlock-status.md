# Crumpet DA1→DA2: mutable runtime source tables and the independent October 2026 unlock assessment

**Research date:** 2026-10-11. **Scope:** Amazon Echo Dot 3rd Gen Refresh **C78MP8** (`crumpet`, MT8167/MT8516, raw NAND), not `donut`. The underlying binary data comes from [MTKClient revision `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9), both stock DA1/DA2 pairs SHA-256 pinned in [the DA1 handoff study](mt8167-da1-runtime-parameter-block-handoff.md). No device, flash operation, firmware patching, agent upload, USB interaction or proprietary binary redistribution.

## 1. New technical result: DA1 passes a **runtime-mutated** state block, not merely static constants

Our [prior instruction-level audit](mt8167-da1-runtime-parameter-block-handoff.md) proved DA1 itself assembles the correct `0xFE4A4D42` magic header, a control flag and two copied sections. This follow-up now cross-references the **two *source* sections** to other real instructions in the same DA1:

| Original pinned DA1 | First copied source (+8, 24B) | Second copied source (+32) | Direct file occurrences of first / second source VMA |
|---|---|---|---|
| `MTK_DA_V5.bin` | `0x00239150` | **`0x002393B8`**, 56 bytes | **1 / 16** |
| `MTK_AllInOne_DA_mt6590.bin` | `0x00222B88` | **`0x00222C50`**, 32 bytes | **1 / 10** |

These counts refer strictly to **literal 32-bit pointers found in the complete original DA1 executable bytes** (signature tail excluded). They are **not** execution frequencies; indirect/derived accesses and future calls may not contain literal addresses. Each source's actual copy-site `LDR` instruction was independently verified to resolve to that original VMA.

The second source is **actively written** by original DA1 code at multiple instruction sites *before or during its operating lifecycle*. Those stores are inside the exact range later copied to DA2; their field types must remain unknown without full data-flow and device runtime instrumentation.

### Verified V5 state-field writes (original A32/Thumb disassembly)

| Original DA1 instruction | Memory field under table base `0x2393B8` | Proven instruction |
|---|---|---|
| `0x2015FA` | `+0x08` = `0x2393C0` | `str r2,[r3,#8]` |
| `0x201A24` | `+0x00` = `0x2393B8` | `str r3,[r4]` |
| `0x201A7C` | `+0x24` = `0x2393DC` | `str r0,[r3,#0x24]` |
| `0x202EC0` | `+0x10` = `0x2393C8` | `str r2,[r3,#0x10]` |
| `0x202EC2` | `+0x14` = `0x2393CC` | `str r2,[r3,#0x14]` |
| `0x202EC4` | `+0x1C` = `0x2393D4` | `str r0,[r3,#0x1c]` |

Separate from the handoff, `0x2010DC` loads the second-source base and `0x2010E2` reads its `+8` field, confirming use of the structure elsewhere in DA1. Other instruction sites read various fields and dispatch via function pointers; **we have not definitively assigned protocol or USB semantics to each copied offset**.

### Verified alternate DA1 state-field writes

| Original DA1 instruction | Memory field under table base `0x222C50` | Proven instruction |
|---|---|---|
| `0x201382` | `+0x18` = `0x222C68` | `str r3,[r5,#0x18]` |
| `0x2014D8` | `+0x1C` = `0x222C6C` | `str r0,[r3,#0x1c]` |
| `0x2025EE` | `+0x0C` = `0x222C5C` | `str r2,[r3,#0xc]` |
| `0x2025F2` | `+0x14` = `0x222C64` | `str r2,[r3,#0x14]` |

`0x20137A` is a verified PC-relative `LDR` of the second-source VMA; `0x201382` then stores into `+0x18`. These are *definite static instructions*; we did not observe which optional branches and callbacks actually execute on any physical Crumpet.

### Consequence for the DA2 `0xFE4A4D42` loop and actual root research

1. DA1's original matched-pair **magic, struct length, R0 handoff** are already consistent by design. This report **does not reopen a static header/size mismatch**.
2. The parameter block also includes **live-changing fields** in the second source. These are prepared/mutated in the DA1 state and then copied into DA2, and could therefore reflect earlier init/callback conditions.
3. **What would need to fail:** active DA1 execution path, state values, source/destination RAM accessibility, indirect function pointer, or USB/DRAM transition. No public Crumpet RAM snapshot records them. Thus neither the **first-word magic gate** nor a **callback-state incompatibility** can honestly be called *the* real hardware root cause yet.
4. Our [original-method 2019 EMI parser defect](crumpet-emi-2019-layout-and-brom-nand-gap.md) remains a directly reproducible upstream input-handling bug; [Stage-2 USB status ambiguities](mtkclient-stage2-nand-profile-transport.md) remain independently supported by host source.

**Research priority:** a *pre-existing, owner-authorized, redacted* Crumpet UART/USB trace showing connection-agent type, DRAM acceptance, DA1 setup result, first 12-byte DA2 XFLASH status read, and any `bootstrap2` diagnostics would help discriminate failure *before the transfer* versus *during DA2 initialization* versus *lost host USB endpoint*. Avoid poking the live SRAM, writing raw NAND or loading arbitrary DA variants on irreplaceable hardware simply to generate a trace.

## 2. Independent current Crumpet unlock status, October 2026

A separate developer maintaining [`Gamer92000/echo-dot-assist`](https://github.com/Gamer92000/echo-dot-assist) explicitly lists:

- **Supported**: Echo Dot 3 **`D9N29T` / `donut`**, Echo Dot 2 `biscuit`, Echo 2 `radar`.
- **Not supported**: Echo Dot 3 Refresh **`C78MP8` / `crumpet`**. The repo directly states that the Dot 3 unlock used for `donut` **does not work** for `crumpet`.

The same independent maintainer's [Home Assistant community update dated October 3, 2026](https://community.home-assistant.io/t/echo-dot-3rd-gen-2018-as-a-fully-local-assist-satellite-keeping-amazons-mic-array-and-wake-word-engine/1025971/36) describes static analysis of a Crumpet unit and reports that known root/custom-boot exploits were patched, pointing to potential **NAND fault/side-channel or JTAG research** instead. **This is the developer's assessment, not an audited proof that all attack surfaces are safe or that root is impossible**. Physical fault and JTAG examples for a *different* Echo Plus/`sonar` are **not validated on Crumpet**.

Some web catalogues (for example [LibreEcho's chip-support catalogue](https://libreecho.org/)) mark `crumpet` "can be unlocked" by referring to `amonet-koboreru`, but [the original project issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2) says its Crumpet raw-NAND path **was never tested** on the real hardware, and the original C source has separately documented [unreachable LK load code](amonet-crumpet-unreachable-lk-and-expdb.md) and [incorrect original function pointers](crumpet-root-unlock-feasibility-2026-10-09.md). The catalogue badge **does not constitute an independent working unlock demonstration**.

**Updated evidence classification (October 11):** Known `donut` installation recipes are neither compatible nor safe for `crumpet`. Public reports have achieved BROM/Kamakiri on certain Crumpet devices, but no reproducible DA2 NAND readback, full ECC/BBT-aware recovery, persistent root, accepted LK unlock credential or custom boot was found.

## 3. Reproducible offline proof

New script: [`scripts/audit_da1_mutable_argument_sources.py`](../scripts/audit_da1_mutable_argument_sources.py).

```bash
python3 scripts/audit_da1_mutable_argument_sources.py \
    /path/to/pinned/mtkclient/mtkclient/Loader
python3 -m unittest discover -s tests -q
```

The script requires **exact SHA-256 hashes of both original DA containers**, verifies the previously proven DA1 copy contract again, checks actual Thumb literal-pool pointers and `STR` register+offset instructions at the listed source locations, rejects write offsets outside the copied source data lengths, and emits **only offsets and metadata**, not DA binaries. It does not execute software on the Echo Dot, patch any binary, access USB or write to NAND.

[Ten synthetic regression tests](../tests/test_audit_da1_mutable_argument_sources.py) cover both mutable table shapes, missing source refs, incorrect Thumb literal, wrong control data source, out-of-bounds field writes, unknown loader identity and fail-closed behavior. All tests use manufactured bytes and patches of the local audit helper; genuine vendor firmware is **not** included.

**Status after this work:** Root and unlock remain unproven. We have established that DA1's second transferred block includes mutable runtime state, *without* conflating static code with observed physical execution. The next robust step is distinguishing the actual DA1 setup/DA2-status pathway from a real Crumpet hardware trace, not an untested boot-chain flash.

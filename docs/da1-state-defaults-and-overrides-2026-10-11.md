# MT8167 DA1: verified default initializer and later override of DA2-bound state

**Date:** 2026-10-11. **Target:** Echo Dot 3 Refresh C78MP8 / crumpet, raw NAND. **Scope:** Offline instruction-level proof with the exact stock MT8167 DA containers from [bkerler/mtkclient at cd25cf9](https://github.com/bkerler/mtkclient/tree/cd25cf9). Neither a DA upload nor a hardware/root experiment. **No proprietary binaries committed.**

## New finding

The prior [mutable-source report](crumpet-da1-mutable-state-and-october-2026-unlock-status.md) demonstrated ten isolated DA1 field stores that target the structures copied into DA2. This follow-up identifies **an additional initialization function for each original DA1** and proves through Thumb instruction decoding that it writes multiple constants into that *same* copied source. It also identifies a later-looking routine that **sets some of the same fields to different values**. "Later-looking" refers to disassembly layout, not proven runtime temporal order: no complete caller/control-flow proof or live RAM trace exists.

- V5 original container SHA-256: `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f`. Initializer at **`0x20254C`** loads **`0x2393B8`** and has **11 verified word stores** inside its 56-byte DA2-bound source. A second routine at **`0x202EB6`** loads the identical base and has **three verified word stores**. The copied source is used at `0x20152E`.
- AllInOne original container SHA-256: `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64`. Initializer at **`0x201D48`** loads **`0x222C50`** and has **seven verified word stores** inside its 32-byte DA2-bound source. Another routine at **`0x2025E4`** loads the identical base and has **two verified word stores**. The copied source is used at `0x201028`.

### Extracted constant writes (each field is a 32-bit word)

These values follow register-setting and `STR` opcodes in the original code. They describe **what each routine writes when it executes**, not the value at DA2 handoff.

| Offset within copied source | V5 initializer `0x20254C` | V5 other `0x202EB6` | AllInOne initializer `0x201D48` | AllInOne other `0x2025E4` |
|---|---|---|---|---|
| `+0x00` | `2` | — | `2` | — |
| `+0x04` | `2` | — | `2` | — |
| `+0x08` | `1` | — | `1` | — |
| `+0x0C` | — | — | `0x1000` | `0x8000` |
| `+0x10` | `0x1000` | `0x8000` | `0x02000000` | — |
| `+0x14` | `0x1000` | `0x8000` | — | `1` |
| `+0x18` | `0x02000000` | — | `1` | — |
| `+0x1C` | — | `0` | `0x68` | — |
| `+0x20` | `1` | — | outside copy | — |
| `+0x24` | `0x68` | — | outside copy | — |
| `+0x28` | `1` | — | outside copy | — |
| `+0x2C` | `0` | — | outside copy | — |
| `+0x30` | `0` | — | outside copy | — |

**Interpretation:** Both independently compiled DA1s use conspicuously similar defaults (`2`, `1`, `0x1000`, `0x02000000`, `0x68`) in related state structures, **but at different offsets and with different copy lengths**. We cannot label these fields as confirmed NAND geometry, DRAM or USB parameters without further call/data-flow proof. The same field can receive both `0x1000` and `0x8000` at different instruction sites; therefore merely inspecting defaults cannot establish final handoff data. This also narrows a possible future comparison: actual runtime state would need to be distinguished from firmware-defined defaults, not guessed based on the DA2 magic.

## Read-only reproducibility

```bash
python3 scripts/audit_da1_state_initializers.py /path/to/pinned/mtkclient/mtkclient/Loader
python3 -m unittest discover -s tests -q
```

The [new static auditor](../scripts/audit_da1_state_initializers.py) checks the **full SHA-256 of both containers**; the established 88/64-byte handoff; exact PC-relative literal references to the second copied source; relevant `mov` constant producers, `str` offsets, field bounds and separate additional-store routines. It fails closed for unexpected images. [Ten synthetic regression cases](../tests/test_audit_da1_state_initializers.py) exercise structure bounds, alignment, write counts, duplicate sites and unknown-loader rejection. Local verification against downloaded stock agents: **both passed**; full offline suite: **232/232 passed**.

## What remains unresolved

No caller graph yet establishes that both initialization paths execute in a particular order on a real C78MP8. More importantly, **we have neither live SRAM values nor a DA2 `SYNC` response or full NAND/OOB readback**. The code does **not** demonstrate a root method. Next: trace the callers of initializer routines and the origin of the **first 24-byte copied source**, and examine any already-recorded, permissioned USB/UART traces to separate absent DA2 reply from re-enumeration. Do not write NAND, mix DA binaries, alter eFuses or attempt unknown boot patches.

# Crumpet MT8167 DA Stage-2: USB status semantics and actual DRAM boundaries

**Research date:** 2026-10-08 · **Research type:** read-only source code, synthetic protocol tests, public Crumpet UART logs, and binary disassembly. No real Echo Dot or Download Agent was executed or modified.

This expands [the DA Stage-2 source audit](mtkclient-da-stage2-analysis.md) and [the direct DA1/DA2 + EMI comparison](da2-binary-emi-compatibility.md).

## 1. The specific `Stage was't executed` message is not a device error code

In the pinned [MTKClient `xflash_lib.py` (`cd25cf9`)](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L288-L321), `boot_to()`:

1. Sends the `BOOT_TO` command and confirms its initial status.
2. Sends an address/size parameter block; for both bundled MT8167 DA2 entries the *declared* address is `0x40000000`.
3. Sends the DA2 content with `send_data()`; a zero status here acknowledges the transfer.
4. Logs `Upload data was accepted. Jumping to stage 2...`, sleeps 0.5 seconds, then invokes `self.status()`.
5. If `status()` **raises an Exception**, prints `Stage was't executed. Maybe dram issue ?.` and returns failure.

The implementation initializes a local status to `-1` *before* that call and catches `Exception` **without recording its class, message, or traceback**. Consequently every such exception reaching this handler is reported identically. It does **not** distinguish a missing or short USB read, malformed protocol frame, timeout or a specific firmware crash. The later `Failed to upload da` message is merely a wrapper.

### Exact reply format expected by the host

The separate [`status()` parser](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py#L138-L161) first reads exactly **12 bytes** as three little-endian 32-bit words: `magic`, `data_type`, `payload_length`. It expects `magic == 0xFEEEEEEF`, then reads `payload_length` bytes and interprets the first 16-bit or 32-bit status value:

| Captured response state | What the code does |
|---|---|
| Full status packet, decoded status `0` | `boot_to()` accepts success |
| Full status packet, status `0x434E5953` (bytes `SYNC`) | `boot_to()` also accepts success |
| Full status packet, nonzero error code | `boot_to()` reports a returned status and failure |
| Full 12-byte header, invalid protocol magic | `status()` returns `-1`; *different* error path from a thrown exception |
| Empty/partial header or an exception reading packet bytes | `struct.unpack` or transport may raise; `boot_to()` prints the generic `Stage was't executed` message |
| Complete header but too few data bytes | `status()` can return `-1` for this condition |
| USB transport itself disconnects | Implementation/transport dependent; **not** proven from the generic message alone |

An additional nuance: the default [PyUSB transport's `usbread()`](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/Connection/usblib.py#L462-L520) retries read timeouts and may return an empty result. Its explicit `No such device` branch calls `sys.exit(1)` (raising `SystemExit`, **not** caught by `except Exception`), so different failures can produce different external logs depending on the active transport and actual execution path.

**Interpretation:** The exact Crumpet community string primarily identifies a **missing usable protocol reply after DA2-transfer acknowledgment**. It is *not proof* that Stage 2 never executed a CPU instruction, nor evidence of the cause of that failure.

### Reproduce the host-side protocol reasoning (zero USB use)

The [read-only XFLASH response decoder](../scripts/decode_xflash_status.py) accepts **only previously captured status-response bytes**, and never opens a device:

```bash
python3 scripts/decode_xflash_status.py --hex 'efeeee fe 01000000 04000000 53594e43'
python3 -m unittest discover -s tests -v
```

This example is a **synthetic** 12-byte header plus `SYNC` success response. It is **not a captured Crumpet packet**. Ten synthetic tests cover success, error status, wrong magic, empty header, partial header/payload and unreasonable lengths. **Do not share unredacted USB captures containing device identifiers or secret data.**

## 2. Independent Crumpet UART logs establish actual normal-boot DRAM range

In the public [Crumpet normal-boot UART log (2021)](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/normal_boot.txt), the bootloader prints:

- `EMI_RAMK0=0x10000000, EMI_RAMK1=0x0`
- `orig_dram start: 0x0000000040000000`
- `orig_dram size: 0x0000000010000000`

The [earlier normal boot log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) independently reports the same one-rank memory map and a successful preloader memory test at the beginning of DRAM, `0x40000000`, with **16,384 passes and zero reported failures**.

Those values describe a total DRAM interval **`[0x40000000, 0x50000000)`** (256 MiB) on the logged device/board. The two independently decoded DA2 startup spans fit well within it:

| DA2 file | Entry branch | DA2 zero-initialized BSS interval | Highest end relative to DRAM base |
|---|---|---|---|
| `MTK_DA_V5.bin` | `0x40000024` | `[0x400559A0,0x4006A520)` | `+0x6A520` |
| `MTK_AllInOne_DA_mt6590.bin` | `0x40000024` | `[0x400315A0,0x400456E0)` | `+0x456E0` |

Thus a **simple physical DRAM capacity shortfall** does **not** explain either candidate being unable to occupy these addresses on a Crumpet with the reported memory map. The boot log also reports reserved ATF ranges around `0x43000000`, well above these DA2 images; however, a normal-boot memory layout does **not** prove what memory protections, pinmux, controller timing, cache state or address mappings apply during the earlier BROM/DA handoff.

The normal-boot memory test does **not** test memory initialized by either Download Agent. Hardware subrevisions may also differ. **DRAM initialization or access errors remain possible; insufficient total DRAM capacity is merely disfavored**.

## 3. Binary prologue comparison narrows—but does not solve—the DA compatibility question

Both DA2 binaries have an identical first **244-byte prologue**, then diverge at a branch into later initialization code. This prologue handles startup relocation, CPU mode-specific stack setup and BSS zero-fill, but points to different literal BSS/data-range endpoints because their program sizes differ.

For DA1 (SRAM stage), both begin with an ARM `B` to offset `+4`. **V5 alone** has `BLX #0x202608` at `0x00200004`; the decoded Thumb target contains `BX LR`, i.e. a simple return. The alternative DA1 goes directly from `0x00200004` into the shared startup's `MRS` / status-control initialization. This particular extra V5 hook alone is **not evidence of a different effective DRAM setup**.

The later DA1 and DA2 implementations differ substantially, and either could have incompatibilities with a specific 0x8167 board revision. We have **not** isolated the exact first divergent instruction executed immediately before the missing Stage-2 acknowledgment.

## 4. What would actually distinguish the remaining hypotheses?

| Candidate explanation | What currently supports it | What existing evidence could distinguish it |
|---|---|---|
| DA2 is present but crashes early | Data transfer acknowledged; no valid reply | Previously captured UART traces showing DA2 prologue/early error output; exact USB transport exception |
| Host loses USB endpoint during DA handoff | Status-frame read fails/returns short | Previously saved USB enumeration/transport logs around the handoff |
| DA2 DRAM initializer or layout incompatible | Two distinct DA2 images, different BSS/driver routines | Specific DA hash and accepted EMI hash correlated with existing device logs |
| Signed DA2 rejected by Stage1 | Stage1 binaries include verification-related diagnostic text | Explicit rejection status / logs from Stage1; current generic timeout is not such a status |
| Wrong total RAM size | Would require DA2 range to exceed physical DRAM | **Disfavored** by confirmed 256 MiB memory map versus sub-megabyte DA2 startup footprint |
| NAND driver incompatibility | DA2 implementations contain different NAND/BMT code | **Not yet testable from existing logs:** NAND discovery is after successful DA2 handshake |

None of the above is proven as the cause for the tested community devices. No root or unlock has been demonstrated.

## Scope and constraints

These findings concern **Crumpet C78MP8, not Donut**. Do not run arbitrary Download Agents on a single non-recoverable device; do not flash, erase, change bootloader fuses or test random address patches based on the above. Our tools and tests never communicate with hardware, and no copyrighted Amazon/MediaTek binary is committed to the repository.

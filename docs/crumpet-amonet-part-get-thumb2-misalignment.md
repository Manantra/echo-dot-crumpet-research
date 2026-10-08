# Crumpet amonet: `PART_GET_ADDR` points into a Thumb-2 instruction (2022 and 2025)

**Research date:** 2026-10-09. **Source:** [R0rt1z2/amonet-koboreru revision `2a28fd0`](https://github.com/R0rt1z2/amonet-koboreru/tree/2a28fd0), [device configuration](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/include/devices/crumpet.h) and [original C function pointer](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/include/preloader.h). **Target:** Crumpet (C78MP8), not Donut.

## What is proven

The published Crumpet header defines `PART_GET_ADDR 0x0020F250`. The C code binds it as:

```c
static void* (*const part_get)(char *name) = (void *)(PART_GET_ADDR | 1);
```

The low bit requests Thumb state. This pointer is used by `bldr_load_part()` (via `part_get(name)`) and by the custom TEE loader. Under the header's own implied ABI, `0x20F250` must be a **callable Thumb entry point**, not an arbitrary halfword of another instruction.

For three **official Amazon Crumpet Preloader images** and the additional **public 2019 Crumpet NAND excerpt**, extracted using HTTP Range and verified against their original OTA compressed-operation and decompressed-partition SHA-256 metadata, we followed the GFH/FILE_INFO file-to-VMA mapping and disassembled the original code linearly from a **locally verified Thumb instruction boundary**:

| Preloader | Full SHA-256 of raw `brhgptpl_0` | `0x20F250` in verified linear Thumb code |
|---|---|---|
| Public 2019 | `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637` | **Second half of 4-byte Thumb-2** `ldr.w r3,[r0,#0x9c]` at `0x20F24E` (bytes `d0 f8 9c 30`). The 2019 archive has two more Amonet TEE pointers inside ASCII strings; see [new root feasibility report](crumpet-root-unlock-feasibility-2026-10-09.md). |
| 2021 | `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` | **Instruction boundary, but inside an existing routine.** At `0x20F250`: `add.w r3, r3, #0x66800`; bytes `03 f5 cd 23`. It uses register state established earlier. |
| 2022 | `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d` | **Second half of a four-byte instruction.** At `0x20F24E`: `adds.w r6, r6, #0x200`; bytes `16 f5 00 76`. `0x20F250` points into the `00 76` trailing halfword. |
| Nov 2025 | `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a` | **Second half of a four-byte instruction.** At `0x20F24E`: `mov.w r2, #0xa00`; bytes `4f f4 20 62`. `0x20F250` points into the `20 62` trailing halfword. |

The 2022 control-flow excerpt begins at the verified `0x20F248` short branch followed by `0x20F24A` `ldr.w`; the 2025 excerpt begins at `0x20F24A` `ldr` then `0x20F24C` `mov`. **Repeated disassembly from different preceding windows gave the same Thumb-2 instruction boundaries.** We did not infer the result by disassembling from the questionable target itself.

**This is a stronger negative result than an ambiguous symbol match**: in two tested firmware images the published `part_get` address is *not even an instruction boundary along the ordinary decoded execution sequence*. Entering there via an indirect Thumb branch would decode the trailing halfword as a new instruction, not invoke the intended existing function.

It is also important **not to overclaim**: a Thumb processor technically can be directed to any suitably aligned halfword; this audit shows it is not the established callable function boundary, not that executing from that byte address is mathematically impossible. The static file-to-VMA mapping is strongly supported by our independent [ARM bootstrap code audit](crumpet-arm-bootstrap-memory-map.md), but the exact live RAM state during an Amonet patch or read callback was **not observed**. These observations do **not** prove the Amonet payload was ever successfully reached on Crumpet.

## Related, less definitive pointer concerns

The same Crumpet header also hardcodes `PART_LOAD_ADDR=0x20F4A8`, `BDEV_INIT_ADDR=0x212E38`, `USB_HANDSHAKE_ADDR=0x20D7DC`, `MTEE_VERIFY_DECRYPT_ADDR=0x21A7EC`, and `TEE_SET_ENTRY_ADDR=0x215FE8`. Their **stored-image bytes and neighboring instruction sequences differ between 2021, 2022 and Nov 2025**. At least some appear to be inner instructions or branch-table/veneer regions rather than identified callable starts. We have **not identified their real functions** or proved all those addresses invalid, because legitimate veneers and alternate entry points exist.

The `PART_GET_ADDR` problem is independently material even if the earlier [source-proven unconditional USB-loop blocker](amonet-crumpet-unreachable-lk-and-expdb.md) were somehow removed. With the original code, `main()` never reaches its normal `part_get("expdb")` path anyway, and `expdb` is absent from the CRC-verified Crumpet GPT. Those are three **distinct** compatibility barriers, not competing explanations for a validated exploit.

## Reproduce without patching anything

New [read-only Thumb-2 boundary verifier](../scripts/audit_crumpet_amonet_part_get_entry.py) intentionally accepts **only these four known SHA-256 images**, verifies a code-anchor fingerprint, uses Capstone for Thumb-2 instruction sizes, and extracts the literal `PART_GET_ADDR` from a local copy of the original device header:

```bash
python3 scripts/audit_crumpet_amonet_part_get_entry.py \
  /path/to/amonet-koboreru/amonet/include/devices/crumpet.h \
  /path/to/verified/2021/brhgptpl_0.bin \
  /path/to/verified/2022/brhgptpl_0.bin \
  /path/to/verified/2025/brhgptpl_0.bin
```

A different image hash fails closed rather than extrapolating function locations. Nine additional [manufactured-byte tests](../tests/test_audit_crumpet_amonet_part_get_entry.py) cover the 2021 instruction boundary, 2022 and 2025 halfword-inside-Thumb-2 cases, unknown firmware, bad code anchors and malformed headers. The tests include only short synthetic instruction fixtures, not whole proprietary images.

**Impact for root/unlock:** It would be unsafe to treat this upstream Crumpet port as a flash-ready path on the official 2022 or November-2025 Preloader. A working exploit requires independently validated **actual runtime function targets** and an independently recoverable NAND storage/boot path. No Crumpet root/unlock, TWRP boot or successful DA Stage 2 is demonstrated by this investigation.

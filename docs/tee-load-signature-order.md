# ATF/TEE boot-loader ordering and verifier call graph (ARM/Thumb)

**Date:** 2026-10-08. **Evidence:** offline ARM Thumb disassembly of independently manifest-hash-verified, official `brhgptpl_0` images. This is **not** a working exploit, payload or flashing procedure.

## Input images and reproducibility

| Image | Preloader build string | SHA-256 of complete OTA partition |
|---|---|---|
| Nov 2022 OTA / Fire OS 6.5.5.5 | `20220323_062523` | `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d` |
| Jan 2024 OTA / Fire OS 6.5.6.1 | `20230726_065225` | `5a107fa6ae4bdf73cb89ab754eada4d6db5c249446fa6292e86964cc1400b298` |
| May 2025 OTA / Fire OS 6.5.6.6 | `20231103_072325` | `7b5600978682929661979138fdf687d13ae5b3a2a1a700f59b3daf3bbb86205b` |

All were retrieved only from public Amazon OTA packages. Their compressed-operation and final partition checksums matched the embedded OTA manifest. The OTA certificate chain was **not** independently authenticated.

**Image mapping:** `FILE_INFO` at file `0x8008`, image start `0x8300`, encoded base `0x00200D00`. Confirmed by ARM boot entry and Thumb PC-relative string references. This is the stored-image mapping, not proof of all live runtime relocation.

## ATF and TEE: separate load, then verify

Both generations perform a first image-load call **followed** by a verification call; they then repeat the process for the subsequent TEE image. These are decoded **direct `BL`** calls, not inferred from log strings.

| Stage | 2022-built image (preloader with old range guard) | 2023-built image (from 2025 official OTA) |
|---|---|---|
| Top-level ATF/TEE loader | `0x20DEC4` | `0x20DF40` |
| ATF **load** call | `0x20DEFA: BL 0x20F1D0` | `0x20DF74: BL 0x20F3AC` |
| ATF **verify** call | `0x20DF10: BL 0x215E80` | `0x20DF90: BL 0x216100` |
| TEE **load** call | `0x20DF36: BL 0x20F1D0` | `0x20DFC6: BL 0x20F3AC` |
| TEE **verify** call | `0x20DF52: BL 0x215E80` | `0x20DFEC: BL 0x216100` |

The `%s %s part. ATF [load|verify] fail` and `%s %s part. TEE [load|verify] fail` diagnostics have separately confirmed PC-relative references within each top-level function, corroborating the stage labels.

### Direct verifier call chains

```text
2022-built:
  0x215E80 --[0x215E8C BL]--> 0x21A5F0 --[0x21A622 BL]--> 0x21A2B0

2023-built (2024 and 2025 official OTA images):
  0x216100 --[0x21610C BL]--> 0x21A870 --[0x21A8A2 BL]--> 0x21A530
```

Both backend wrappers inspect image metadata, call a deeper verifier, and propagate its return value. The exact certificate coverage, authentication invariants and cryptographic implementation were **not** fully audited.

## Where the memory-range checks occur

The most important distinction is **inside the image-load routines**, before they return to the top-level verifier.

### Older loader, compiled March 2022

```text
0x20F1D0  image-loading function begins
0x20F218  BL 0x20210C     [first/pre-read]
0x20F2FE  BL 0x20F0C0     [older overlap/range guard]
0x20F328  BL 0x20210C     [subsequent image data read]
...returns to caller...
0x20DF10 / 0x20DF52       [separate verification call]
```

The old guard at `0x20F0C0` reads from a four-entry region-name table via `0x215848`, checks stored boundaries, and references `check_part_overlapped failed`. Upstream [amonet-koboreru](https://github.com/R0rt1z2/amonet-koboreru) describes an image-name-dependent path through this implementation. Merely identifying this code does **not** show exploit success on Crumpet.

### Newer loader, compiled July/November 2023

```text
0x20F3AC  image-loading function begins
0x20F3F8  BL 0x20210C     [first/pre-read]
0x20F420  BL 0x20F368     [extract image header fields]
0x20F490  BL 0x20F1A0     [address-and-length range guard]
0x20F494  CBNZ r0        [branch on safe result]
0x20F50E  BL 0x20210C     [subsequent image data read]
...returns to caller...
0x20DF90 / 0x20DFEC       [separate verification call]
```

There is a **second** independently decoded call to the same guard at `0x20F68E` in a different load routine, with return-value handling at `0x20F692`.

The new guard `0x20F1A0` takes a **candidate address and length**, invokes `0x20E3D8` for text- and BSS-region comparisons, and returns a result used at both call sites. It **does not compare the image-name string** in this wrapper. This means changing the header name cannot simply select the old name-table early-return path *within this new guard*. Other checks or paths could still depend on the name.

Crucially, the guard explicitly checks against the preloader's protected **text/BSS ranges**; the [subsequent static memory-map audit](sram-guard-exploit-intersection.md) confirms that the published payload's block-device target `0x001086EC` is within the protected BSS range `[0x00102180,0x00109DAC)`. This does **not** establish that every possible alternative SRAM target is protected. Testing the exploit's address/length edge cases would require further exact header-value tracing and a reliable model of all additional checks and relevant memory maps.

### 2024 vs 2025 OTA images

The instruction bytes in the top-level TEE loader (`0x20DF40` region), image-load function (`0x20F3AC` region), overlap guard (`0x20F1A0`), and MTEE verification path examined were identical across the January 2024 OTA and May 2025 OTA images. Thus the reconstructed call-chain results apply to both **the July 2023 and November 2023 build strings** at the inspected addresses.

## What is established, and what is NOT

**Established by direct decoded calls:**
- Both builds load first, then call the signature-verification wrapper.
- Both make an initial data read and a later data read inside the lower-level loader.
- The new range guard is invoked between those two reads, before the later read.
- The older name-table-specific check is replaced by a numeric address/length guard at the traced call site.
- The new verifier still dispatches to a deeper image-verification path; it was not simply removed.

**NOT established:**
- Whether the first `0x20210C` call reads only header bytes in every path or can be influenced to read other content; the ordering and function calls are verified, but every argument and length has not been independently proven.
- Whether crafted address `0xFFFFFFFF` falls back to zero in the new implementation or how all size and address arithmetic behaves in corner cases.
- **Partly resolved:** the guard's encoded BSS interval contains the exact block-device target used in the published exploit. We still need to establish how malicious header values are translated before the guard receives its effective address/length; see [SRAM audit](sram-guard-exploit-intersection.md).
- Whether the TEE/ATF signature is validated over all header fields.
- Whether BROM/DA, anti-rollback or raw-NAND write permissions permit safe use of *any* exploit.
- That the official OTA image with a 2023 build string exactly matches a community device dump.

## Reproduction, safely

Use a **locally obtained** official preloader image and Capstone:

```bash
python3 scripts/disassemble_preloader.py /path/to/official-preloader.bin --address 0x20df40 --length 0xe0
python3 scripts/trace_preloader_calls.py /path/to/official-preloader.bin --begin 0x20df40 --length 0xe0 --target 0x20f3ac --target 0x216100
python3 scripts/trace_preloader_calls.py /path/to/official-preloader.bin --begin 0x20f3ac --length 0x190 --target 0x20210c --target 0x20f1a0
```

These tools inspect bytes offline. No proprietary firmware is uploaded to this repository. Never flash, downgrade or patch a real device based on this analysis.

Related: [ARM memory-guard comparison](arm-range-check-analysis.md), [verified firmware timeline](verified-preloader-timeline.md), [upstream exploit explanation](https://github.com/R0rt1z2/amonet-koboreru).

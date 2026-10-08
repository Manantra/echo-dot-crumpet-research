# Crumpet TEE header handling, effective load address, and overlap protection

**Research date:** 2026-10-08. **Status:** independently checked against official Crumpet OTA preloader images. No live device was used and no firmware is distributed.

This expands the [TEE load and signature ordering analysis](tee-load-signature-order.md) and the [SRAM guard / exploit intersection](sram-guard-exploit-intersection.md).

## What the published attack actually asks the preloader to do

In [upstream `create_tee_image.py`](https://github.com/R0rt1z2/amonet-koboreru/blob/main/create_tee_image.py), Crumpet's device configuration yields:

- `BDEV_ADDR = 0x001086EC`
- Block-device read callback: `0x0010870C` (`BDEV_ADDR + 0x20`)
- Crafted data size: **`0x00108804` bytes**
- Header name changed to **`lk`**
- TEE subimage header's `memory_address` set to **`0xFFFFFFFF`**

The upstream explanation expects the crafted TEE data to be copied starting at address zero, reaching and replacing the read callback in SRAM.

## The newer loader's header-processing path

The official Jan-2024 OTA contains `brhgptpl_0` SHA-256 `5a107fa6ae4bdf73cb89ab754eada4d6db5c249446fa6292e86964cc1400b298`, with embedded build string `20230726_065225`. The official May-2025 OTA contains SHA-256 `7b5600978682929661979138fdf687d13ae5b3a2a1a700f59b3daf3bbb86205b`, with embedded build string `20231103_072325`.

These exact call sites were decoded as Thumb `BL` instructions in **both** images:

| Call site | Target | Observed role |
|---|---|---|
| `0x20F3F8` | `0x20210C` | Initial block read; caller passes size `0x200` |
| `0x20F420` | `0x20F368` | Parse metadata from initial image-header buffer |
| `0x20F476` | `0x2160F4` | Query mode used for TEE address computation |
| `0x20F47E` | `0x216130` | Conditionally compute or transform target address |
| `0x20F490` | `0x20F1A0` | Validate effective destination and data size |
| `0x20F494` | — | `CBNZ r0, #0x20F4A6`: continue only on accepted guard result |
| `0x20F50E` | `0x20210C` | Later large image-data read |
| `0x20F68E` | `0x20F1A0` | Range guard in alternative loader path |
| `0x20F6FE` | `0x20210C` | Subsequent read in alternative path |

The load sequence is **header read → header parse → possible address transform → guard → large data read**. This is an analysis of decoded call order in the normal image-load path; it does not prove every possible control-flow path behaves identically.

### The header fields being parsed

The helper at `0x20F368` first checks the header magic. In its recognized-image case, it performs:

```text
0x20F372  LDR r5, [r0,#0x28]   ; address-like field
0x20F37A  STR r5, [r1]         ; candidate destination
0x20F37C  LDR r1, [r0,#0x04]   ; size-like field
0x20F37E  STR r1, [r2]         ; candidate data size
0x20F380  LDR r2, [r0,#0x2C]   ; additional header field
0x20F384  STR r2, [r3]
```

These fields feed the subsequent destination/size checks. Their semantics in unusual malformed images need further analysis; the register comments reflect observed use, not verified vendor source types.

### TEE-specific mode and address transform

The upper-level ATF/TEE loader invokes `0x2160E8` at `0x20DFB8` with `r0=1` before loading the second TEE subimage. The lower-level loader queries the same state via `0x2160F4`, and conditionally calls `0x216130` with the candidate address. A later call to `0x2160E8` is present at `0x20DFE4` on the successful second-image path.

Within `0x216130`, a mode-dependent branch chooses between initialization and an existing stored result. In the initialization path, Thumb instructions align the input address to a 4-KiB boundary and compare it with a limit of `0x0C000000` before performing further allocation/storage work:

```text
0x21613A  CMP   r3,#0
0x21613C  BNE   #0x2161C8
0x216140  UBFX  r3,r0,#0,#0xC
0x216144  SUBS  r0,r0,r3
0x216148  CMP.W r0,#0x0C000000
0x216154  BLS   #0x216164
0x216160  BL    #0x2107BC     ; diagnostic/failure path
```

**Important:** This does *not* prove the exact effective destination for `memory_address=0xFFFFFFFF`. The initializer is stateful, and its control flow branches according to previously initialized data. We have **not** established the complete behavior of its fallback/error path. It is enough to show that blindly equating this header field with a zero destination on newer builds is unwarranted.

## The target is protected even on the upstream attack's own assumptions

The new wrapper `0x20F1A0` reads protected BSS boundaries from initialized literal-referenced data:

```text
BSS: [0x00102180, 0x00109DAC)
Published target BDEV_ADDR: 0x001086EC
Published callback: 0x0010870C
Proposed destination: 0x00000000
Proposed length: 0x00108804
```

Under those assumed inputs, the copy interval **`[0x00000000, 0x00108804)`** overlaps the protected BSS interval and includes the targeted callback. The helper at `0x20E3D8` implements unsigned range-overlap comparisons with arithmetic-overflow handling; the new wrapper calls it for text and BSS regions.

In the documented normal loading path, the guard at `0x20F490` precedes the later large read at `0x20F50E`. Its failure result reaches a diagnostic/error path at `0x20F4A2`, rather than the direct success branch. Thus the published **name-based `lk` overlap bypass is not reproduced in this new guard**, which takes destination and length rather than a name string.

## After loading: verification is still present

The new top-level routine at `0x20DF40` calls the image loader at:

- `0x20DF74: BL 0x20F3AC` (first ATF image) followed by `0x20DF90: BL 0x216100` (verification/decode wrapper).
- `0x20DFC6: BL 0x20F3AC` (second TEE image) followed by `0x20DFEC: BL 0x216100` (verification/decode wrapper).

This independently corroborates that the **memory guard runs within the load operation, before the separate verifier**. The downstream verifier and all of its cryptographic decisions have **not** been exhaustively audited.

## Evidence, implications and limitations

**Strongly supported:** On the official inspected 2023-era builds, the ordinary loading path subjects the effective destination and size to a numeric overlap guard before the bulk image read. The guard's BSS interval includes the exact callback that the published overwrite targets. A rename of the TEE subimage to `lk` does not skip this numeric guard via the old name-table mechanism.

**Not established:** A formal proof of non-exploitability, every possible malformed-header translation, whether another loader path can evade the guard, the consequences of all failure-handling paths, safe NAND flashing/downgrade or persistent root on hardware.

## Reproduce without writing or flashing firmware

Using a preloader image locally obtained from the original Amazon OTA:

```bash
python3 -m pip install 'capstone>=4,<6'
python3 scripts/inspect_guard_chain.py /path/to/official-2023-era-crumpet-preloader.bin
python3 scripts/disassemble_preloader.py /path/to/official-2023-era-crumpet-preloader.bin --address 0x20f368 --length 0x36
python3 scripts/disassemble_preloader.py /path/to/official-2023-era-crumpet-preloader.bin --address 0x216130 --length 0x90
python3 -m unittest discover -s tests -v
```

All tools are read-only. **Do not flash or downgrade a Crumpet based on this research.** Original firmware and proprietary binaries are not uploaded to this repository.

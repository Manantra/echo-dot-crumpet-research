# ARM-level comparison: Crumpet preloader memory-range guards

**Analysis date:** 2026-10-08. **Method:** read-only static ARM/Thumb disassembly (Capstone 4) of independently SHA-256-verified `brhgptpl_0` partitions from official Amazon Crumpet OTAs. No hardware involved; no firmware redistributed.

## Input artifacts

| OTA | Embedded preloader build | Full image SHA-256 (`brhgptpl_0`) |
|---|---|---|
| Nov 2022 / Fire OS 6.5.5.5 | `20220323_062523` | `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d` |
| Jan 2024 / Fire OS 6.5.6.1 | `20230726_065225` | `5a107fa6ae4bdf73cb89ab754eada4d6db5c249446fa6292e86964cc1400b298` |
| May 2025 / Fire OS 6.5.6.6 | `20231103_072325` | `7b5600978682929661979138fdf687d13ae5b3a2a1a700f59b3daf3bbb86205b` |

See [verified OTA timeline](verified-preloader-timeline.md) and [read-only Range-based retriever](../scripts/remote_ota_probe.py).

## Establishing file-to-address mapping

All three official OTA images contain a MediaTek `MMM/FILE_INFO` header at file offset **`0x8000`** with encoded load address **`0x00200D00`**. A recognizable ARM `b` instruction to `0x00200D18` lies at the encoded code entry point +4 bytes, specifically file offset **`0x8304`**.

For inspection, we therefore use:

```text
candidate_file_offset = 0x8300 + (candidate_virtual_address - 0x00200D00)
```

This mapping is internally corroborated by the ARM entry instruction **and** by decoded literal/PC-relative references to specific diagnostic strings. It remains **a mapping of the stored bootloader image**, not proof of the complete live preloader memory map or runtime relocations.

## Preloader built 2022-03-23: older range checking path

- **`0x0020F0C0`**: function with Thumb prologue `push.w {r4, r5, r6, r7, sb, lr}`.
- **`0x0020F0C4`–`0x0020F0CE`**: observes a length-related bound using `mvns`, `ldr`, `cmp`, `bls`.
- **`0x0020F0FA`–`0x0020F116`**: iterates over four stored region descriptors, calling `0x00215848`.
- **`0x0020F118`–`0x0020F138`**: explicit unsigned comparisons with range endpoints.
- **`0x0020F13C`–`0x0020F148`**: computes the address of literal `[%s] check_part_overlapped failed` via `ldr r0,[pc,#0x70]; add r0,pc` and calls a diagnostic function at `0x00210E1C`.
- **`0x0020F302`–`0x0020F30A`**: cross-reference to `[%s] check_part_overlapped done` and a logging call.
- One decoded Thumb caller of this checker appears at **`0x0020F2FE`**.

The code checks several boundaries, but a vulnerability cannot be inferred solely from these instructions.

## Preloader built 2023-07-26: a different explicit guard

The later image has **new code**, not just a renamed diagnostic:

- **`0x0020F1A0`**: starts a wrapper that compares the requested load range against two independently derived protected memory regions.
- **`0x0020F1B4`**, **`0x0020F1E2`**: calls to the helper **`0x0020E3D8`**.
- **`0x0020F1BC`–`0x0020F1CA`**: a decoded PC-relative reference to `[%s] %s: load range overlap text region`, then a diagnostic call.
- **`0x0020F1E8`–`0x0020F1F4`**: similarly references `[%s] %s: load range overlap bss region`.
- **`0x0020F1FA`–`0x0020F1FE`**: success result in `r0`, then return.
- Confirmed Thumb `BL` call sites to the wrapper occur at **`0x0020F490`** and **`0x0020F68E`**, followed by conditional handling of its return value.

The helper at **`0x0020E3D8`** is small and independently interpretable:

```text
0x20E3D8  push  {r4, r5, lr}
0x20E3DA  subs  r4, r1, #1
0x20E3DC  adds  r4, r4, r0
0x20E3DE  bhs   #0x20E3F2
...
0x20E3F6  cmp   r4, r2
0x20E3F8  blo   #0x20E3F2
0x20E3FA  cmp   r0, r5
0x20E3FC  ite   hi
0x20E3FE  movhi r0, #0
0x20E400  movls r0, #1
```

In context this behaves like an **unsigned interval-overlap predicate** for a pair of (start, length) ranges, with handling of integer carry/overflow and zero lengths. The wrapper uses it to check both **text** and **BSS** segments. Distinguish **observed code and branches** from interpretation of the compiler-generated routine's exact preconditions.

The image with embedded **2023-11-03** build date from the 2025 OTA contains **identical instruction bytes** at the new helper and wrapper addresses inspected above, indicating this new guard survived at least until that image.

## Why this matters

This gives **positive code-level evidence of a substantially changed bounds-checking implementation** between the builds dated 2022-03-23 and 2023-07-26. The old diagnostic's disappearance was not merely a string-strip artifact in these images.

However:

1. This does **not** show that the public `amonet-koboreru` exploit succeeds on the older build.
2. It does **not** independently prove the new guard fixes every metadata-overlap vulnerability.
3. It does **not** establish the execution order of all TEE/ATF signature checks or that any source build is safe to flash.
4. The public 2019 NAND excerpt uses a different file-wrapper layout; dynamic exploit patch addresses still need version-specific validation.
5. The OTA image with build `20231103_072325` is **not yet shown to match** the community's complete 2023 device-dump SHA-256.

## Reproduce the disassembly (no flashing)

1. Obtain the original Amazon OTA yourself via its link in [FTVDB](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json) and inspect it with [our OTA parser](../scripts/ota_inventory.py). The Python disassembler accepts *local* preloader images as inputs; it does not extract or save proprietary firmware on its own.
2. Install **Capstone** in your own environment: `python3 -m pip install capstone`.
3. Run `python3 scripts/disassemble_preloader.py /path/to/your/image.bin --address 0x20e3d8 --length 0x2a`, or `--address 0x20f1a0 --length 0x60` on the appropriate image version.
4. Run `python3 -m unittest discover -s tests -v` for synthetic image mapping tests.

**Do not flash, downgrade or modify a device based on these findings.** No working Crumpet unlock has been established.

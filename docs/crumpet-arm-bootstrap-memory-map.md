# Crumpet Preloader ARM bootstrap: decoded BSS zeroing and indirect Thumb handoff

**Date:** 2026-10-09. **Scope:** public [2019 NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin), official Amazon Crumpet OTA `brhgptpl_0` components from 2021, 2022 and November 2025, each official component hash-verified against its original CrAU OTA manifest. **No device, no firmware write, no payload or patch generated.**

This is an independent instruction-level check supporting—but not conclusively proving at runtime—the [stored-image address mapping used in the amonet patch-site audit](amonet-hardcoded-patch-address-audit.md). The new [`audit_preloader_bootstrap.py`](../scripts/audit_preloader_bootstrap.py) decodes these fields by verifying **17 exact A32 instruction words** rather than relying on symbol names or guesses.

## 1. Identical ARM startup instructions, but firmware-specific data/Thumb continuation

Across all four builds:

1. MediaTek `GFH/FILE_INFO` encodes code load address **`0x00200D00`**. The NAND image stores that entry at `0x6300` (2019 wrapper) or `0x8300` (2021 and later wrapper).
2. At `0x00200D04`, instruction **`0xEA000003`** branches to `0x00200D18` (ARM state).
3. At `0x00200DB0` and `0x00200DB4`, A32 PC-relative **`LDR` instructions** take BSS start/end address literals from `0x00200D08` and `0x00200D0C`.
4. Instructions at `0x00200DC4`, `0x00200DC8`, `0x00200DCC`, `0x00200DD0` implement a **32-bit zero-fill loop**: `STR r2,[r0]`, increment by 4, compare against the end, loop while unequal. This is **direct evidence** that the literals are intended to initialize SRAM BSS and not merely decorative strings.
5. At `0x00200DD4`/`0x00200DD8`, the bootstrap loads two additional control/source pointers from the `+0x10`/`+0x14` literals. At `0x00200DDC`, it loads a fixed marker `0xDEADBEFF` and at `0x00200DE0` writes it to the control slot. Further source/register use occurs at `0x00200DE4`–`0x00200DF0`. The actual **runtime value** read at the source pointer has not been observed, and cannot safely be inferred by blindly reading the *same offset in a stored NAND image*.
6. At `0x00200DF4`, the bootstrap reads its next argument `0x00201000` from a PC-relative literal. It branches via the ARM `LDR PC,[PC,#-4]` at `0x00200E4C`, whose literal at `0x00200E50` contains a firmware-dependent **odd** target address (Thumb bit set). We verify that this target maps inside the corresponding stored image.

**The entire inspected A32 opcode sequence is byte-identical across these generations.** The data literals used by that code are not. This independently corroborates the encoded VMA and shows exactly where subsequent executable control flow can change.

## 2. Verified build-by-build values

| Property | 2019 public dump | 2021 official OTA | 2022 official OTA | Nov 2025 official OTA |
|---|---|---|---|---|
| Encoded ARM entry | `0x200D00` | same | same | same |
| Stored entry offset | `0x6300` | `0x8300` | `0x8300` | `0x8300` |
| BSS start | `0x102180` | `0x102180` | `0x102180` | `0x102180` |
| BSS end, exclusive | `0x1097FC` | `0x1097FC` | `0x1097FC` | `0x109DAC` |
| BSS clear length | 30,332 bytes | 30,332 bytes | 30,332 bytes | 31,788 bytes |
| Control slot for `0xDEADBEFF` | `0x102AA4` | `0x102AA4` | `0x102AA4` | `0x103050` |
| Subsequent runtime-source pointer | `0x222754` | `0x22279C` | `0x22282C` | `0x222998` |
| Handoff argument | `0x201000` | same | same | same |
| ARM→Thumb continuation literal | `0x20E34D` | `0x20E34D` | `0x20E375` | `0x20E40D` |
| Mapped Thumb continuation stored file offset | `0x1394C` | `0x1594C` | `0x15974` | `0x15A0C` |

**Nuance:** Identical literal *addresses* do not imply identical instructions at the target. The 2019 and 2021 ARM→Thumb pointer both say `0x20E34D`, but their corresponding Thumb bytes differ significantly: the 2019 mapped target starts with a short branch, while the 2021 target starts with `mov r0,r4`. Even without relocation, comparing only address numbers across builds misidentifies code behavior.

### Historical image fingerprints

- **2019:** `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`.
- **2021:** `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5`.
- **2022:** `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d`.
- **November 2025:** `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a`.

## 3. What this resolves about amonet-koboreru root/unlock

The upstream [Crumpet Amonet hardcoded patch sites](amonet-hardcoded-patch-address-audit.md) include `0x217F2C` (claimed DA verification bypass), `0x2019B0` (anti-rollback), `0x201954` (fuse-related), `0x217548` (USB) and `0x20E19C` (TEE load).

The audited ARM bootstrap adds **independent, executable A32 evidence for the stored-file-to-VMA mapping** used to inspect these addresses. The observed 2019 `0x217F2C` landing inside the readable USB diagnostic `[USB]addr: 0x6A, value: %x` therefore cannot reasonably be dismissed solely because the 2019 NAND wrapper has a different `GFH` offset.

On the other hand, **neither the static A32 startup nor the ARM→Thumb continuation independently observes the running preloader's complete RAM map at Amonet patch time**. A BROM-provided state, memory relocation, stage-dependent overwrite, or a different donor binary could change the live situation. We have not traced those. The mismatch remains a **strong compatibility/safety blocker**, not a proof that every exploit path is impossible.

The published Amonet BDEV target `0x001086EC` and read callback field `0x0010870C` are **within all four verified SRAM BSS spans**. This is consistent with the intended block-device-function-pointer attack surface, but **says nothing by itself** about whether the modified TEE image can reach or overwrite that area. In the 2023+ loader the [post-update guard](sram-guard-exploit-intersection.md) explicitly protects the larger BSS span.

## 4. Read-only reproduction

```bash
python3 scripts/audit_preloader_bootstrap.py \
  /path/to/public-2019-preloader.bin \
  /path/to/official-2021-preloader.bin \
  /path/to/official-2022-preloader.bin \
  /path/to/official-2025-preloader.bin

python3 -m unittest discover -s tests -v
```

The parser rejects any image with a different key A32 opcode, unaligned/out-of-bounds BSS, malformed Thumb continuation or invalid GFH mapping. Eight new synthetic tests do **not** contain Amazon/MediaTek binary data. The auditor neither writes firmware nor communicates with a device.

**Next unresolved question:** establish actual in-memory relocation/handoff state after the BootROM starts the Preloader, and correlate static function boundaries/TEE load guards for any exact version allegedly supported by Amonet. **No root/unlock is proven. Do not write fuse, NAND, LK, TEE or preloader from these addresses.**

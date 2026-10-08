# Crumpet amonet patch-site audit against five verified Preloader builds

**Date:** 2026-10-08 · **Device:** Crumpet / Echo Dot 3rd Gen Refresh (C78MP8). **Conclusion:** The publicly released Crumpet amonet patch-site constants **cannot be independently validated** as the claimed function entries using any of the five available historical stored-image address maps. They must **not** be blindly applied to a real device.

**Sources:** [`R0rt1z2/amonet-koboreru` at commit `2a28fd0`](https://github.com/R0rt1z2/amonet-koboreru/tree/2a28fd0), especially [`devices/crumpet.c`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/devices/crumpet.c) and [`patch.c`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/patch.c); [public 2019 NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin); verified official Amazon Crumpet preloader components from 2021, 2022, 2024, November 2025, indexed by [FTVDB](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json).

No device was connected; no code or bootloader was patched, built, loaded or flashed. Official OTA components were SHA-256 verified against their own CrAU manifests (not publisher signatures).

## 1. What the upstream Crumpet port actually does

`devices/crumpet.c` requests these **five absolute addresses**:

| Claimed function/purpose in source | Operation | Address |
|---|---|---|
| Allow unsigned Download Agents | `patch_ret(..., 0)` | `0x00217F2C` |
| Do not restore USB descriptor pointers | `patch_word(...)` | `0x00217548` |
| Disable anti-rollback version check | `patch_ret(..., 0)` | `0x002019B0` |
| Prevent anti-rollback fuse increment | `patch_ret(..., 0)` | `0x00201954` |
| Redirect the TEE loader | `patch_branch(...)` | `0x0020E19C` |

The [actual upstream patch helper](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/patch.c) calls `writel(value, addr)` inside `patch_word` and `writew(..., addr)`/`writew(..., addr+2)` when inserting a Thumb branch. `patch_ret` delegates to `patch_word` to write a Thumb `movs r0, <return>` + `bx lr` sequence.

**Therefore that helper itself performs no build-based address resolution or relocation.** This is direct source-code evidence, not evidence that RAM necessarily has the same layout as a flash image.

The upstream project's main README explicitly warns about downgrade/brick risks; the `crumpet.c` port was not documented as independently working on real Crumpet hardware.

## 2. Five local images and the validated *stored-file* VMA mapping

The MediaTek GFH `FILE_INFO` contains an encoded load address `0x00200D00`. Each file has a recognizable ARM branch at the code entry (`FILE_INFO + 0x300`).

| Image | Size | GFH position | Code-entry file offset | SHA-256 |
|---|---:|---:|---:|---|
| Public 2019 NAND excerpt | 196,608 | `0x6000` | `0x6300` | `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637` |
| 2021 Amazon OTA | 184,320 | `0x8000` | `0x8300` | `a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5` |
| 2022 Amazon OTA | 184,320 | `0x8000` | `0x8300` | `990cfcfa861c96e4bec53da32347b14b9cf44847f84f188c226cea820532083d` |
| 2024 Amazon OTA | 184,320 | `0x8000` | `0x8300` | `5a107fa6ae4bdf73cb89ab754eada4d6db5c249446fa6292e86964cc1400b298` |
| Nov-2025 Amazon OTA | 184,320 | `0x8000` | `0x8300` | `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a` |

The source-to-image mapping used for read-only disassembly is:

```text
stored_file_offset = executable_entry_file_offset +
                     (candidate_RAM_address - encoded_load_address)
```

It is corroborated by the ARM entry and other mapped instructions/PC-relative strings in [our earlier static analyses](arm-range-check-analysis.md). **It is not, on its own, a measurement of actual runtime SRAM layout.** An [additional opcode-level audit of the ARM startup](crumpet-arm-bootstrap-memory-map.md) now independently validates the same embedded entry and literal BSS zeroing in four historical builds, plus the actual indirect ARM→Thumb continuation. This materially strengthens *stored-image* address interpretation, but still does not observe later live memory at `apply_patches()` time. A relocation or transformed address in a real boot session could invalidate the mapping.

## 3. The absolute amonet targets do not correspond to an unchanged instruction signature

The following table reports the **first four stored-image bytes** at the mapped candidate address. Hex values differ substantially across the images:

| Declared target | 2019 | 2021 | 2022 | 2024 | 2025 |
|---|---|---|---|---|---|
| DA acceptance `0x217F2C` | `2c207661` | `78443349` | `32463c23` | `12d11b4b` | `12d11b4b` |
| USB descriptors `0x217548` | `4b0a0070` | `024b7b44` | `c2d80000` | `34237944` | `34237944` |
| ARB check `0x2019B0` | `66330023` | `014698b1` | `014698b1` | `014698b1` | `014698b1` |
| Fuse burn `0x201954` | `ab4231d0` | `0ff04efa` | `0ff062fa` | `0ff096fb` | `0ff096fb` |
| TEE loader `0x20E19C` | `d0f8a430` | `2bfe3e4b` | `474b3946` | `00240cf0` | `00240cf0` |

**Most decisive observation:** In the **2019 file**, mapped `0x217F2C` lands inside the literal ASCII string:

```text
[USB]addr: 0x6A, value: %x
```

A Thumb `patch_ret` at that location would overwrite the data bytes of the string, *not* a function entry, **under the stored-image mapping**. The 2019 USB-descriptor target is also adjacent to `protocol mispatch` / USB diagnostic strings.

Other examples:

- **2022 `0x217548`** maps to `c2 d8 00 00 06 d9 ...`, consistent with a **data/literal-table candidate**, not a positively identified USB descriptor assignment function entry. Thumb decoding at an arbitrary aligned address is not proof of executable code.
- **2021/2022/2024/2025 `0x2019B0`** all start with `mov r1, r0; cbz r0, ...` in *our arbitrary-offset Thumb interpretation*. No prologue, call-site map, or distinctive anti-rollback evidence has yet identified this as the intended ARB check.
- **2021 `0x20E19C`** starts in undecodable Thumb bytes at that exact halfword address; the 2022 and 2024/2025 locations decode differently. This is **not** proof of a stable TEE loader entry.
- **2024 and 2025** are byte-identical at all five mapped sites because the MediaTek GFH-anchored payload in those samples is unchanged. It does not confer function identity.

**Why this matters:** The patch list is not a cross-version proof of valid patch sites. In particular, `patch_ret` replaces four bytes and assumes the address represents a safe callable Thumb function entry. Inserting such bytes into a conditional branch, a literal pool, or the middle of a function can corrupt unrelated code/data or cause an unrecoverable boot failure.

## 4. Limits and safe next research

We have **not** established where Crumpet's RAM-resident Preloader is *actually* relocated at the moment `amonet-koboreru` invokes `apply_patches()`. The source may have been authored against an unexamined binary with different addresses or a runtime image; without confirming its compiled code, symbol maps, call sites and executing address, it is not possible to assign accurate replacement patch sites. A successful BROM/Kamakiri entry is **not** that verification.

The older 2021/2022 binaries do contain an older overlap diagnostic, while the 2019 dump does not, and the newer 2024/2025 code contains the rewritten guarded loader. **String presence alone neither proves exploitability nor validates these hardcoded patch addresses**. [Relevant earlier analyses](arm-range-check-analysis.md).

**Recommended non-destructive evidence:**
- An already available owner-authorized preloader **RAM snapshot or symbol map** at the exact patching stage, if any exists, to establish load/relocation and executable Thumb boundaries.
- Exact binary/version that the upstream amonet Crumpet configuration used when its authors selected these five values.
- Static call-graph/symbol confirmation for each claimed DA verification / ARB / fuse / USB / TEE function *before* considering any live test.
- A separately validated raw-NAND backup/restore path including ECC/OOB and bad-block handling.

**No working Crumpet root/unlock confirmed. Do not apply these addresses to a device.** Neither the new [read-only patch-site auditor](../scripts/audit_amonet_patch_sites.py) nor its tests write firmware, generate an exploit payload, or contact hardware.

## 5. New October 2026 public claim: LibreEcho's roadmap is **not** independent proof of a Crumpet unlock

The [LibreEcho hardware roadmap](https://libreecho.org/) currently labels `crumpet` **"Access implemented"**, but its cited access basis is **`amonet-koboreru`** itself—the same unverified Crumpet port audited here. The LibreEcho homepage and [upstream README](https://github.com/aslater3/LibreEcho) specify that the actual published stable release and one-shot installer target **Echo 2nd Gen / `radar`, not Crumpet**. The matrix explicitly distinguishes access from a finished/validated OS port.

An independent participant [reported on October 3, 2026](https://community.home-assistant.io/t/echo-dot-3rd-gen-2018-as-a-fully-local-assist-satellite-keeping-amazons-mic-array-and-wake-word-engine/1025971/36) that current Crumpet firmware blocked known root methods after static analysis. This is also a **third-party unverified conclusion**, rather than a formal security proof that no vulnerability exists.

**Evidence decision:** The LibreEcho green marker should not be presented as a demonstrated Crumpet success without an actual Crumpet hardware log, firmware/board revision, confirmed DA2/secure-boot state and independently repeatable recovery procedure. Equally, an absence of known root methods does not prove that root is theoretically impossible.

## Reproduce without writing to hardware

```bash
python3 scripts/audit_amonet_patch_sites.py \
    /path/to/amonet-koboreru/amonet/devices/crumpet.c \
    /path/to/amonet-koboreru/amonet/patch.c \
    /path/to/archived/2019/brhgptpl_0.bin \
    /path/to/manifest-verified/2021/brhgptpl_0.bin \
    /path/to/manifest-verified/2022/brhgptpl_0.bin \
    /path/to/manifest-verified/2024/brhgptpl_0.bin \
    /path/to/manifest-verified/2025/brhgptpl_0.bin
```

Install `capstone>=4,<6` for supplementary Thumb disassembly; otherwise hex/ASCII and validated GFH-to-file mappings still work. Every finding refers to the **specific SHA-256 identified above**, not "all Crumpet models."

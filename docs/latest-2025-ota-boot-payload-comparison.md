# Crumpet latest catalogued OTA (Nov 2025): unchanged LK and GFH-anchored Preloader image

**Research date:** 2026-10-08. **Device:** Crumpet / C78MP8, MT8167 family, raw NAND. **Scope:** Official Amazon CDN OTA binaries indexed by [FTVDB](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json), the most recent catalogue entry being Fire OS **6.5.7.1 / NS6571/6208**, dated **2025-11-28**. This is a catalogue date, not a claim that no newer unpublished firmware exists.

**Integrity method:** each selected `CrAU` payload partition was obtained via bounded HTTPS Range requests. We checked the compressed `REPLACE_XZ` operation SHA-256 and final decompressed partition SHA-256 against the *same original update manifest*. **The Amazon OTA publisher signature was not independently authenticated.** No proprietary images were committed or written to disk. No real device was accessed.

## 1. LK bootloader has not changed in the newly sampled 2025 releases

The `lk` partition in the official OTAs of **2025-05-15**, **2025-07-24**, **2025-10-09** and **2025-11-28** is exactly the same SHA-256-verified image (also verified previously in **2024-01-09**):

- LK size: **237,568 bytes**.
- LK SHA-256: **`c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d`**.
- Embedded build: **`20230407_002912`**.
- The `flash:unlock`, `flash:otucert`, `flash:otucode` and Amazon one-time certificate verifier strings remain.
- The firmware-specific [decoded Fastboot authorization path](lk-fastboot-unlock-disassembly.md) is thus **unchanged for this LK build**.

There is **no evidence here of a newer unrestricted Fastboot unlock**. The presence of those command strings is not authorization to unlock.

## 2. Raw NAND preloader partition checksums vary while the GFH-anchored image does not

Our comparison covers the `brhgptpl_0` partition, **184,320 bytes** for each sample. Its MediaTek `MMM\x01` GFH header is at **file offset `0x8000`**. Across these four official 2025 updates, the **entire byte span `[0x8000, 0x2D000)`** is **bit-for-bit identical**.

**GFH-anchored span SHA-256 in all four OTAs:**

`4e8a844d65e1e0b48512e93011ff4e1bfe78cf72d17ed66daff5cd70ab9da189`

The full *partition* hashes differ:

| Official OTA | Embedded Preloader build | Whole `brhgptpl_0` SHA-256 |
|---|---|---|
| 2025-05-15, NS6566/6813 | `20231103_072325` | `7b5600978682929661979138fdf687d13ae5b3a2a1a700f59b3daf3bbb86205b` |
| 2025-07-24, NS6569/6009 | `20231103_072325` | `de8dcdb67c15a2b090ad24ebe126a89aa0bf08f705881c216f869b261cfd89a8` |
| 2025-10-09, NS6571/6176 | `20231103_072325` | `725463811c16b0d197afa1857a00fd8e9b2c98aec12afcf02b8ec6e1217130bf` |
| 2025-11-28, NS6571/6208 | `20231103_072325` | `837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a` |

Measured pairwise differences, always exclusively **before** the GFH anchor:

| Comparison | Byte changes in full raw partition | Earliest–latest changed byte | Changes at or after `0x8000` |
|---|---:|---|---:|
| May → July 2025 | 308 | `0x3010`–`0x489F` | **0** |
| July → October 2025 | 307 | `0x3010`–`0x489F` | **0** |
| October → November 2025 | 308 | `0x3010`–`0x489F` | **0** |
| May → November 2025 | 309 | `0x3010`–`0x489F` | **0** |

The start-of-partition `[0x0,0x8000)` is the **raw NAND preamble** in these OTA images, not the examined MediaTek GFH-anchored payload. Its exact fields (NAND boot metadata, checksum, signature, etc.) **have not been conclusively decoded**. Do not label all changed bytes as signatures or presume this header may be rewritten safely.

**Interpretation:** A difference between two **whole `brhgptpl_0` SHA-256 values does not establish different executable Preloader code**. For these official 2025 updates, no differences were found within the complete GFH-anchored Preloader payload. The same observation cannot be generalized to all board revisions or in-device NAND contents.

## 3. Latest November 2025 OTA: all four Preloader copies carry the same GFH image

We independently downloaded and verified `brhgptpl_0`, `brhgptpl_1`, `brhgptpl_2`, and `brhgptpl_3` from **the same 2025-11-28 OTA**. Every partition has the identical GFH-anchored image SHA-256 above.

Their *whole-partition* hashes differ because of just **four bytes**, at exactly `0x100D`, `0x1011`, `0x101D`, `0x1021` relative to copy 0. The byte values correlate with the 0/1, 4/5, 8/9, 12/13 copy offsets:

| Raw preloader copy | Byte at `0x100D` | Byte at `0x1011` | Byte at `0x101D` | Byte at `0x1021` |
|---|---:|---:|---:|---:|
| `brhgptpl_0` | 0 | 1 | 0 | 1 |
| `brhgptpl_1` | 4 | 5 | 4 | 5 |
| `brhgptpl_2` | 8 | 9 | 8 | 9 |
| `brhgptpl_3` | 12 | 13 | 12 | 13 |

These fields plausibly index NAND boot pages / redundant copies, **but that semantic interpretation remains a hypothesis**. There is no evidence the four copies contain four different executable Preloader variants, nor any suggestion to alter these bytes.

## 4. What this changes for root/unlock research

- The **latest catalogued 2025 LK** has not acquired a new bypassable Fastboot unlock implementation relative to our previously verified 2024/2025 image.
- The **four sampled 2025 preloader GFH payloads are identical**, despite different full-partition hashes. Looking for a *new 2025-specific image-layout exploit* by treating those full-hash differences as different code would be a false lead.
- The real [post-2023 SRAM/BSS guard](sram-guard-exploit-intersection.md) remains relevant for the GFH image examined here. Same core means no guard regression *within the sampled 2025 OTA GFH payloads*.
- Earlier genuinely different Preloader builds, BROM/Download-Agent compatibility, authorized unlock credentials and a validated NAND restore strategy remain separate research questions.
- [MTKClient issue #26](https://github.com/bkerler/mtkclient/issues/26) shows the **same Stage-2 timeout on a separate MT6739 device** despite BROM/Kamakiri and a patched DA. The maintainer suggested a valid Preloader EMI, and the reporter said several Preloader versions did not resolve the failure. This is a **cross-chip counterexample** to asserting that the generic Stage-2 message uniquely proves a Crumpet-specific mitigation, security policy, or raw-NAND failure. It does *not* identify the real Crumpet cause.

**No functional root, persistent unlock, NAND write/recovery method or signed credential has been confirmed.**

## 5. Reproduction (fully read-only)

With the two **original indexed Amazon HTTPS OTA URLs**:

```bash
python3 scripts/compare_official_preloader_payloads.py \
  'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin' \
  'https://d1s31zyz7dcc2d.cloudfront.net/2025/11/28/7dba93cd-a7ab-4ba6-ba00-cfcb859d5a7a/update-kindle-crumpet-NS6571_user_6208_0012584501380.bin'

python3 scripts/compare_official_boot_copies.py \
  'https://d1s31zyz7dcc2d.cloudfront.net/2025/11/28/7dba93cd-a7ab-4ba6-ba00-cfcb859d5a7a/update-kindle-crumpet-NS6571_user_6208_0012584501380.bin'

python3 -m unittest discover -s tests -v
```

The tools download only the small preloader operations and their OTA manifests; they compare partition bytes **in memory**, print only hashes, offsets and counts, and do not save or share proprietary binaries.

**Research boundary:** Never write the NAND prefix, transplant signed images between devices, downgrade `brhgptpl_*`, or mix the four redundant copies without a proven recovery process.

# Verified Crumpet LK image timeline (2021–2025)

**Research date:** 2026-10-08. Original Amazon firmware is **not** redistributed here. Each image was reconstructed offline by fetching only the relevant OTA `payload.bin` XZ operation from the official historical Amazon CDN, then verifying **both** the compressed operation SHA-256 and the final `lk` partition SHA-256 against the `CrAU` update manifest. This establishes extraction integrity, not independently verified OTA publisher signatures.

| Crumpet official OTA release | LK embedded build stamp | `lk` bytes | Verified LK SHA-256 |
|---|---|---:|---|
| Sep 2021 / Fire OS 6.5.4.8 | `20210414_064357` | 233472 | `82794651a7f977dcd67adec52eabd19db0c09897ef68445d2dc8335c30b496bf` |
| Nov 2022 / Fire OS 6.5.5.5 | `20220827_065252` | 237568 | `0dfc2e7a08c60f2bea180a8462c743aec1e0b4093d82cb99ecf80c5d3e4d8454` |
| Jun 2023 / Fire OS 6.5.5.9 | `20221005_064411` | 237568 | `139499dcefb15ddf2f9a80f72622a5609bfdf2029ca203f4f1b92f17f9493836` |
| Jan 2024 / Fire OS 6.5.6.1 | `20230407_002912` | 237568 | `c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d` |
| May 2025 / Fire OS 6.5.6.6 | `20230407_002912` | 237568 | `c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d` |

Source URLs are indexed in [FTVDB's original Crumpet OTA catalogue](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json).

## Does older LK provide an obvious unrestricted unlock route?

All five SHA-256-verified LK images contain these ASCII signatures:

- `flash:unlock`, `flash:otucert`, `flash:otucode`
- `amzn_verify_onetime_unlock_code`
- `the command you input is restricted on locked hw`

These are **string-presence observations**, not claims that the five versions have identical instruction semantics or accept the same commands. We decoded a concrete generic `flash:` command dispatcher, unlock data validator and separate certificate/code handlers for the **May 2025 / Jan 2024 LK build**; see [ARM call graph](lk-fastboot-unlock-disassembly.md).

Important exact **byte-comparison** results using matching file offsets in the full 237,568-byte images:

- **Jun 2023 OTA → Jan 2024 OTA**: only **270 different bytes** in the whole image. The following regions are **exactly identical**:
  - LK unlock validation routine `[0x1B10, 0x1CAF)`;
  - one-time certificate/code handlers `[0x1DC8, 0x1E60)`;
  - Fastboot command registration `[0x1E5B4, 0x1E72A)`;
  - flash subcommand dispatcher `[0x1F7C0, 0x1F90C)`;
  - diagnostic bytes `[0x24E00, 0x255C0)`.
- **Jan 2024 OTA → May 2025 OTA**: `lk` partition is **fully byte-for-byte identical**, including SHA-256. The 2025 OTA did **not** introduce a different LK unlock mechanism.
- **Nov 2022 OTA → Jun 2023 OTA**: the registration and flash-dispatch slices above are also **identical** at their file offsets, but the unlock-validation slice has 12 differing bytes. Their semantic role has not yet been independently matched instruction by instruction.
- **Sep 2021 OTA → Nov 2022 OTA**: build layout and full image size differ, making naive equal-offset comparison misleading. The certificate/locked-hardware diagnostic strings are still present in both.

**Conclusion:** No historical Crumpet LK examined here offers evidence of an obvious unrestricted Fastboot unlock. It would be especially unjustified to assume that a 2023→2024 or 2024→2025 LK downgrade changes the verified vendor certificate gate. That does not prove no alternate vulnerability or authorized Amazon token could exist.

## Reproduction

Use [our read-only OTA Range script](../scripts/remote_ota_probe.py) to inspect listed Amazon OTA manifests and optionally verify the `lk` partition via `--include-lk`. The [LK-specific disassembler](../scripts/inspect_lk_unlock.py) validates the exact Jan 2024/May 2025 LK hash before attempting to interpret its absolute file offsets.

No real Crumpet hardware was accessed, no firmware flashed, no official images shared. Avoid all bootloader downgrades without a proven restore mechanism.

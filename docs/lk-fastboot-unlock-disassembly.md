# Crumpet LK vendor Fastboot unlock handler — ARM/Thumb call graph

**Research date:** 2026-10-08. **Evidence:** read-only examination of a SHA-256-verified `lk` partition from Amazon's official Crumpet Fire OS OTA. This document **does not** describe a functional production unlock and **does not** advise transmitting any data to a real device.

## Precisely identified image

- Amazon official [May 2025 Crumpet OTA, Fire OS 6.5.6.6](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json).
- Reconstructed OTA `lk` partition: **237,568 bytes**, build string `20230407_002912`.
- SHA-256 of the reconstructed uncompressed partition: **`c4e87b94b1fb0a39bdf23e4d1aadeee55d422072b5a2b43ca3e91275e250b69d`**.
- Both the compressed-payload and final partition checksums were checked against the update-engine manifest. The OTA package's signing-certificate chain was **not** independently authenticated.
- All addresses in the tables below are **FILE OFFSETS** in this exact image, **not runtime VMAs**. Its header begins at file offset zero (MTK signature `0x58881688` and `LK` label) and its ARM vector/code begins at file offset `0x200`. Its usual execution region contains Thumb code.

## New result: Generic Fastboot command prefix and three subcommands

A previously found `flash:unlock` string is **not** sufficient to conclude that an independent `flash:unlock` command is registered directly. We now have verified the following:

| Step | File offset | Decoded fact |
|---|---|---|
| Generic command registration | `0x1E658 → 0x1E666` | A PC-relative `flash:` string at `0x34BEA` is passed to a `BL 0x1E110` registration function |
| Fastboot command registration routine | `0x1E110` | Creates command-list entries with supplied prefix, function pointer and flags |
| Subcommand comparison `unlock` | `0x1F7F4`–`0x1F7FA` | PC-relative string `unlock` at `0x2DF8A`, then string comparison `BL 0x20C36` |
| Validation of unlock data | `0x1F804` | `BL 0x1C48` with caller-supplied data pointer and size |
| Check validation result | `0x1F808` | `CBZ r0, #0x1F818`: only success proceeds via this branch |
| Downstream unlock checker | `0x1CA6` | `BL 0x1B10` inside the unlock-data validation chain |
| Subcommand comparison `otucert` | `0x1F84E`–`0x1F854` | PC-relative `otucert` at `0x2DF97`, comparison `BL 0x20C36` |
| `otucert` handler | `0x1F85E` | `BL 0x1DC8`, separate handler and length check |
| Subcommand comparison `otucode` | `0x1F86C`–`0x1F876` | PC-relative `otucode` at `0x2DFA5`, comparison `BL 0x20C36` |
| `otucode` handler | `0x1F87C` | `BL 0x1E18`, separate handler and length check |

We decoded **actual direct Thumb `BL` instructions** and **PC-relative literal references**, rather than merely finding matching ASCII substrings. Their local code paths are consistent with a generic Fastboot `flash:` dispatcher that treats `unlock`, `otucert` and `otucode` as special subcommands.

The string-matching helper `0x20C36` checks the requested suffix and branches to the corresponding handler.

### Additional guards in the vendor handlers

The `otucert` handler at `0x1DC8` contains a comparison with **`0x250`** at `0x1DF0`; the `otucode` handler at `0x1E18` compares with **`0x100`** at `0x1E40`. The full set of their input-format semantics is not yet proven, but both reject certain unexpected request lengths.

The `unlock` handler calls `0x1C48`, which performs preliminary checks, uses routines `0x1B178` and `0x1B13C`, then invokes `0x1B10` to validate the supplied data. A non-success result leads to an `unlock code error` diagnostic; **the success branch is not taken merely because the command exists**.

The same `lk` image contains certificate-related messages such as `amzn_verify_unlock`, `amzn_verify_onetime_unlock_code` and `Verify one time unlock cert fail`. Historic [Crumpet Fastboot UART traces](https://github.com/jvandewiel/no-alexa/wiki/Fastboot) actually report `Verify one time unlock cert fail, ret = -5` and `the command you input is restricted on locked hw` for commands on production-locked units.

**Interpretation:** A certificate- or signed-code-conditioned vendor unlocking path is present, but we have **not established any publicly obtainable accepted signing credential or legitimate issuance service**. This does not demonstrate a working bootloader unlock or a verifier bypass.

## Important false positive: LibreEcho hardware compatibility matrix

The [LibreEcho development roadmap](https://dev.libreecho.org/) labels `crumpet` **“Access implemented”**, but cites **only** `amonet-koboreru` as its source for that claim. In [upstream issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2), the author states explicitly that the Raw-NAND Crumpet port has **not been tested** on the device and is on hold due to bricking risks. The [LibreEcho product README](https://github.com/aslater3/LibreEcho) says the current supported product is Echo 2nd Gen (`radar`/Puffin) and Crumpet is merely future porting scope.

Therefore **LibreEcho's green “access implemented” badge is not independent proof** of an actual functional Crumpet unlock. Do not use LibreEcho Radar/Donut installers or one-shot commands on a Crumpet unit.

## Follow-up BROM/DA observation

Third-party [Crumpet BROM reports](https://github.com/R0rt1z2/amonet-koboreru/issues/2) document some devices with BROM/Kamakiri access but Stage-2 DA failure. Similar **Stage-2 response timeouts exist on other MediaTek NAND and eMMC devices** in the [MTKClient project issue tracker](https://github.com/bkerler/mtkclient/issues/317). Therefore Stage-2 timeout alone is **insufficient to identify a NAND-specific cause or a confirmed hardware mitigation**; model and logs are required. Neither Root nor NAND write access has been demonstrated.

## Reproduce the exact LK cross-reference and call checks

With the *locally and lawfully obtained* matching official `lk` partition (the script rejects other SHA-256 hashes):

```bash
python3 -m pip install 'capstone>=4,<6'
python3 scripts/inspect_lk_unlock.py /path/to/local-lk.bin
python3 -m unittest discover -s tests -v
```

The script only reads bytes, verifies the complete SHA-256, checks decoded Thumb `BL` call destinations, and independently resolves the four `LDR Rt,[PC]` / `ADD Rt,PC` string references. It does **not** create a certificate, modify LK, emit payloads, or contact devices.

## Current root feasibility verdict

- **Working persistent Crumpet unlock/root:** still **not independently demonstrated**.
- **Amazon vendor unlock control flow:** partly independently verified at machine-code level.
- **Necessary next evidence:** identify **legitimately issued signing material/authorization**, if any; otherwise continue non-destructive boot-chain and BROM/DA research with a recovery plan.
- **No-brick rule:** do not try arbitrary `flash:unlock`, `flash:otucert` or `flash:otucode` commands on a locked unit based on static evidence.

This research is for owner-authorized devices; Amazon proprietary images are *not* hosted in this repository.

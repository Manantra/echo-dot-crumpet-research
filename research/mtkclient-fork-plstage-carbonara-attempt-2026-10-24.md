# mtkclient fork — plstage carbonara, DA_IMAGE_SIG_VERIFY_FAIL, 2026-10-24

Follow-up to [mtkclient-plstage-carbonara-attempt-2026-10-24.md](mtkclient-plstage-carbonara-attempt-2026-10-24.md), which recorded five attempts on the upstream commit `cd25cf9`: four never sent a single byte, one got partial handshake errors and I/O failures. This session used the same fork described in [mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md](mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md) — `GrahamKowalski/mtkclient`, commit `6d6c1c9` — and ran `plstage --skipwdt --ptype carbonara`.

## Setup

Same Raspberry Pi 3 with `dwc_otg.speed=1`, same spare Crumpet unit, same venv. Command: `mtk.py plstage --skipwdt --ptype carbonara`. Three separate power cycles, usbwatch running throughout.

## What happened (observed)

Three attempts across three power cycles:

- **Attempt 1:** Device detected as `0e8d:2000 MT65xx Preloader` at Full Speed. Identification completed fully: CPU MT8167, HW code `0x8167`, subcode `0x8a00`, HW Ver `0xcb00`, SW Ver `1`, target config `0x0`, all flags false. `Main - Connected to device, loading`. Then: `Preloader - upload_data failed with error: DA_IMAGE_SIG_VERIFY_FAIL (0x2001)`. `Error on uploading da data`. `Error on sending pl`. Exited cleanly.

- **Attempt 2:** Same result, byte for byte. Clean connect, full identification, `DA_IMAGE_SIG_VERIFY_FAIL (0x2001)`.

- **Attempt 3:** Never caught the device — mtkclient was still in its polling loop when the device completed its own boot. Recorded as a timing miss, not a failure of the connection path.

## What this means, and what it does not

`DA_IMAGE_SIG_VERIFY_FAIL (0x2001)` is a named, specific status code returned by the preloader in response to an upload attempt. It is not a communication error, a timeout, or a crash primitive failure. The preloader received the uploaded data, verified its signature, and explicitly rejected it.

This is the first session in this project where `plstage` connected reliably and reached the upload step. The earlier upstream attempts (four connection failures out of five) never got here. Whether the fork's changes to the connection path are responsible for the reliability improvement is not confirmed — those changes were aimed at the dispatch and `run_dump_preloader` path, not the connection setup — but the correlation is noted.

The `DA_IMAGE_SIG_VERIFY_FAIL` result directly engages the open conflict already documented in this project: `gettargetconfig` reads target config `0x0` with all flags including SBC false, but the board's own boot log shows `sec params sbc_enabled = 1` and `Detect production device: True`. This session provides a third data point. The preloader is enforcing signature verification on uploaded images regardless of what `gettargetconfig` reports. I am not claiming to have resolved which of the two readings is "correct" or what is causing the discrepancy — that remains open — but this result is consistent with the board's own boot log, not with the `gettargetconfig` reading.

`Carbonara.patchda1_and_upload_da2()` did not run. That method requires DA1 to have been loaded and running before it can patch it; the failure happened at the upload step before DA1 executed. This is not a finding about whether the Carbonara patch bytes are present or absent in this preloader build.

## Connection reliability comparison

| Session | Upload reached | Connect attempts | Result |
|---------|---------------|-----------------|--------|
| Upstream `cd25cf9`, `plstage --ptype carbonara` | No (0/5) | 5 | 4× zero bytes sent; 1× I/O errors mid-handshake |
| Fork `6d6c1c9`, `plstage --skipwdt --ptype carbonara` | Yes (2/2 that connected) | 3 (1 timing miss) | DA_IMAGE_SIG_VERIFY_FAIL both times |

The `--skipwdt` flag was not used in the upstream session; it is not known whether that alone accounts for the difference.

## Recovery

Device booted normally after all three sessions. No stuck-loop behaviour on any recovery boot observed during this session. Did not run a UART capture specifically for recovery this round; the absence of stuck-loop is consistent with prior recovery observations.

## Not established

- Whether the upload failure is specifically about the DA binary mtkclient is using (MTK_DA_V5.bin), an OEM signature requirement, or both.
- Whether a correctly signed DA, if one existed and were available, would be accepted.
- What the `gettargetconfig` target config `0x0` / `sbc_enabled: False` reading actually represents. This conflict between that result and both the board's boot log and this session's upload rejection is open and unresolved.
- Whether `check_for_carbonara_patched()` would report a patched or unpatched preloader on this build. DA1 never ran.
- Whether the connection reliability difference between the upstream and fork sessions is reproducible or session-specific.

## Handling

No DA executed on the device. No flash was read or written. Raw session logs are not included here.

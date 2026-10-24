# mtkclient fork -- printgpt carbonara, unpatched DA upload, DA_IMAGE_SIG_VERIFY_FAIL, 2026-10-24

Follow-up to [mtkclient-fork-plstage-carbonara-attempt-2026-10-24.md](mtkclient-fork-plstage-carbonara-attempt-2026-10-24.md). That session sent an unsigned generic payload via `plstage` and got `DA_IMAGE_SIG_VERIFY_FAIL`. A session recorded the same day using `printgpt --ptype carbonara` with the SBC gate fix applied got `DA_IMAGE_SIG_VERIFY_FAIL` again, but in that session the host was also applying local patches to the DA binary before upload. This session uses a further fork modification that suppresses those host-side patches when `--ptype carbonara` is set, so the device receives the original, unmodified `MTK_DA_V5.bin`. The question is whether `DA_IMAGE_SIG_VERIFY_FAIL` is caused by the host-side patches invalidating the signature, or whether the device refuses even the original unmodified binary.

## Fork state

Same fork and Pi setup as [mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md](mtkclient-fork-crash-modes-0-3-attempt-2026-10-24.md): `GrahamKowalski/mtkclient`, branch `fix/crasher-mode3-and-run-dump-preloader`, base commit `6d6c1c9`. Two additional local modifications were made to `mtkclient/Library/DA/xflash/xflash_lib.py` in this session, not yet committed to the fork at time of testing:

1. **SBC gate fix** (applied in the immediately prior session): `patchda1_and_upload_da2()` was previously gated on `target_config["sbc"]` being True. Since `gettargetconfig` returns `sbc_enabled: False` on this device, the Carbonara stage-2 method was never called. The fix adds `or self.mtk.config.ptype == "carbonara"` to the condition.

2. **DA1 patching bypass** (applied this session): `upload_da1()` was applying host-side patches to the DA binary unconditionally when `target_config["sbc"]` was False, because `not False` evaluates to True. These patches modify the binary and invalidate its MTK signature. The fix adds a check: when `ptype == "carbonara"`, skip the patching step entirely and send the DA binary as-is.

Command: `python3 mtk.py printgpt --skipwdt --ptype carbonara`

## Bench setup issue identified and resolved

Every session attempt from approximately 15:59 onward was failing at the USB handshake stage with repeated `DeviceClass - Couldn't detect device. Is it connected?` messages, even though `dmesg` on the Pi confirmed the device was appearing correctly as `0e8d:2000 MT65xx Preloader`. This was traced to missing udev rules: `mtkclient/Setup/Linux/*.rules` (specifically `50-android.rules`, `51-edl.rules`, `52-mtk.rules`) had never been copied to `/etc/udev/rules.d/` on the Pi. Without them, `libusb` cannot open the device as a non-root user, and all device detection fails silently at the `get_active_configuration` level.

Copying those three files to `/etc/udev/rules.d/` and reloading udev restored normal operation. Earlier successful sessions (events 001 and 002 in the usbwatch record, roughly 15:44--15:48) had been working, which implies the rules were present on the Pi at that point; they were apparently absent after a subsequent change in the session. The Pi was also rebooted as part of diagnosing this, and `cdc_acm` was blacklisted via `/etc/modprobe.d/blacklist-mtk-preloader.conf`; that blacklist was not the fix for the detection failures, but it remains in place.

The two-hour gap between the last successful handshake and the session that ultimately succeeded was almost entirely consumed by diagnosing this setup issue, not by the device or the DA signing question.

## What happened (observed)

With the udev rules in place and the DA1 patching bypass applied, one attempt connected cleanly:

- Device detected as `0e8d:2000 MT65xx Preloader` at Full Speed. Full identification completed: CPU MT8167, HW code `0x8167`, subcode `0x8a00`, HW Ver `0xcb00`, SW Ver `1`, target config `0x0`, all flags false.
- `DaHandler - Device is unprotected.`
- `DaHandler - Device is in Preloader-Mode.`
- `DAXFlash - Uploading xflash stage 1 from MTK_DA_V5.bin`
- No "Patching da1" or "Patching da2" log lines. The DA1 patching bypass is working: the binary was sent without modification.
- `Preloader - upload_data failed with error: DA_IMAGE_SIG_VERIFY_FAIL (0x2001)`
- `Error on uploading da data` / `Error on sending DA.` / `Failed to upload da.`

Session log: `session_udev_fixed.txt`, 56 lines, same length as the immediately prior session which used a patched DA.

## What this means, and what it does not

`DA_IMAGE_SIG_VERIFY_FAIL (0x2001)` is returned by the preloader whether the uploaded binary is patched or unpatched. The host-side patches were not causing the failure; they were a secondary issue. The device is rejecting `MTK_DA_V5.bin` as-is, with its original bytes and its original MediaTek-issued signature intact.

This is consistent with the board's own boot log showing `sec params sbc_enabled = 1` and `Detect production device: True`, and inconsistent with `gettargetconfig` reporting all security flags false. The preloader is enforcing signature verification, as the boot log suggests. The fact that the standard MTK-signed DA is rejected indicates that the preloader verifies against a key other than MediaTek's own DA-signing key -- consistent with a production Amazon device configured to accept only OEM-authorised download agents. This is stated as a consistent observation, not as a proven causal chain; the exact mechanism of the signature verification on this build has not been independently established.

`Carbonara.patchda1_and_upload_da2()` was not reached. It requires DA1 to be running on the device before it can patch anything in memory. DA1 never executed.

## Implication for Carbonara

The Carbonara exploit requires a DA binary that the device's preloader will accept and execute. On this device, the preloader rejects `MTK_DA_V5.bin` regardless of whether it has been patched or is unmodified. Without a DA that passes the device's signature verification, Carbonara has no path forward through the standard mtkclient DA set.

This does not speak to what an OEM-signed DA, if one were ever obtained from another source, would do on this device. It also does not address whether the preloader itself contains the Carbonara-vulnerable patch bytes in a form that would matter, since that check (`check_for_carbonara_patched()`) requires DA1 to execute first. Both remain unestablished.

## Recovery

Device booted normally after the session. UART capture confirmed `BOOT_TIME`, `sec params sbc_enabled = 1`, `Detect production device: True`, LED ring, normal kernel console. No flash was read or written.

## Not established

- Whether the preloader is using Amazon's own signing key, a restricted MTK key, or some other mechanism. The observed fact is that `MTK_DA_V5.bin` is rejected; the reason is inferred, not independently proven.
- Whether any DA binary signed with a key this preloader accepts exists outside of Amazon's own signing infrastructure.
- Whether the Carbonara-vulnerable patch bytes are present or absent in this preloader build.
- Whether the `gettargetconfig` result (`sbc_enabled: False`) is a misread, a different security domain, or something else. That conflict remains open.

## Handling

No DA, certificate, or device-specific key material was used or produced beyond what the preloader's rejection response implies. Raw session logs are not included here.

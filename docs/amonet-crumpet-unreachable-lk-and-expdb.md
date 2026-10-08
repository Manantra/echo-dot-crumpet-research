# Critical Crumpet amonet port blockers: unconditional USB loop and missing LK partition

**Verified:** 2026-10-09. **Devices:** Amazon Echo Dot 3rd Gen Refresh *Crumpet* C78MP8. **Source revision:** [`R0rt1z2/amonet-koboreru` commit `2a28fd0`](https://github.com/R0rt1z2/amonet-koboreru/tree/2a28fd0). **Mode:** read-only static C-source audit, synthetic unit tests, CRC-validated **2019 public Crumpet NAND GPT** and SHA-256-manifest-verified **Nov 2025 Amazon Crumpet OTA GPT**. **No payload compiled, flashed, executed or loaded onto a real device.**

### Executive result

The existing open-source Crumpet port does **not** currently implement a verifiable persistent root/custom LK boot path **even if its earlier preloader exploit could successfully invoke the payload**:

1. **Certain source-level dead end at USB download mode under normal C function semantics:** `crumpet.c` forces the download-key detector true, while `preloader.h` supplies an always-true cable-detection stub on devices lacking `USB_CABLE_IN_ADDR`—including Crumpet. `main.c` calls `enter_usbdl(0)` *before* attempting to load a replacement LK. That call enters `do_usb_handshake()`, which has an unconditional `while (1)` without a source exit. Therefore `bldr_load_part(LK_PART_NAME, ...)` is **not reached on the ordinary successful-entry code path**.
2. **LK destination not represented in the actual Crumpet GPT:** the port declares `LK_PART_NAME "expdb"`, while all **18 CRC-verified, active partitions** from the public 2019 Crumpet excerpt and the official Nov 2025 Crumpet OTA contain **no `expdb`**. Instead there are `lk_a`, `lk_b`, `boot_a`, `boot_b`, etc. The entire OTA preloader image also has **no literal ASCII `expdb`**. This is strong evidence that the named target is not a real standard Crumpet GPT partition. A special, *as-yet unverified* alias in firmware `part_get()` cannot be excluded from the table alone.
3. **Not a self-contained build/install route:** upstream `build.sh crumpet` requires `tees/tee_crumpet.img` as a stock donor, but the checked-out public repository **does not ship this file**. The wrapper exits immediately with `error: no donor TEE for 'crumpet'`. This could be remedied by *lawfully obtaining the correct stock image* and does **not**, by itself, prove a device vulnerability or platform incompatibility.

These three independent facts must **not** be confused with proving that a Crumpet payload executes or that bootloader security is bypassable; neither has been shown.

## 1. Source-level proof of the nonreturning USB branch

At the pinned upstream revision:

- [`include/devices/crumpet.h`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/include/devices/crumpet.h) defines `PLATFORM mt8516`, `LK_PART_NAME "expdb"` and **does not define `USB_CABLE_IN_ADDR`**.
- [`include/preloader.h`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/include/preloader.h) provides `static inline int usb_cable_in(void) { return 1; }` if `USB_CABLE_IN_ADDR` is absent. We also searched the used `platform/mt8516` and generic platform headers, and found **no alternative macro definition** for this build. Other devices *do* define this macro, showing that the omission is specific to the configuration and not simply a missing source file.
- [`devices/crumpet.c`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/devices/crumpet.c) overrides `usbdl_detect_key()` with unconditional `return 1;`, explicitly commented as a **temporary forced download mode**.
- [`usbdl.c`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/usbdl.c) contains `if (force || (usb_cable_in() && usbdl_detect_key())) do_usb_handshake();`, and `do_usb_handshake()` wraps `usb_handshake(...)` and a delay in **`while (1)` with no break or return**.
- [`main.c`](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/main.c) first calls `apply_patches()`, `setup_usb_descriptors()`, `boot_device_init()`, then **`enter_usbdl(0)`**, and only **later** `bldr_load_part(LK_PART_NAME,...)`, followed by `return -1` to continue the Preloader's TEE fallback.

The resulting *source-conditional* path is:

```text
Assume vulnerable Preloader executes the forged BDEV read callback
  -> Crumpet payload start.S / main()
  -> apply_patches()                    [not proven to be valid on this firmware]
  -> setup_usb_descriptors()
  -> boot_device_init()
  -> enter_usbdl(0)
       force == 0
       usb_cable_in() == 1             [compile-time inline fallback]
       usbdl_detect_key() == 1        [Crumpet-specific override]
       condition = 0 || (1 && 1) = 1
       -> do_usb_handshake()
            -> while (1) { usb_handshake(...); mdelay(2500); }
  X  never returns by ordinary C flow:
       bldr_load_part("expdb", ...)     [not reached]
       return -1;                      [not reached]
```

The loop may fail due to hardware exceptions or external reset; that is **not** evidence of a safe return, a working unlock or persistent boot. This report explicitly does **not** propose bypassing the condition or executing an untrusted payload to probe it.

## 2. Independent on-device partition *format* check (no physical device accessed)

We parsed original, CRC-valid GPT structures from:

| Source | GPT active partition count | Contains `expdb`? | Contains `lk_a` and `lk_b`? |
|---|---:|---|---|
| [Public 2019 Crumpet NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) | 18 | **No** | **Yes** |
| Official [November 28, 2025 Crumpet OTA](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json) | 18 | **No** | **Yes** |

Both have the same logical partition names and ranges documented in [our 2019–2025 NAND/GPT research](crumpet-nand-gpt-2019-2025.md). The official OTA compressed and uncompressed partition SHA-256 were checked against its own CrAU manifest (without verifying publisher signature independently).

The [port's `bldr_load_part()` implementation](https://github.com/R0rt1z2/amonet-koboreru/blob/2a28fd0/amonet/include/preloader.h) asks `part_get(name)`, and **returns `-1` if that lookup is null**. On the nominal Crumpet GPT mapping, `part_get("expdb")` has no corresponding named entry. Whether it could resolve an undocumented alias from a separate table **has not been reverse-engineered**, so this is a **strong partition-name mismatch**, not a proof that every possible firmware implementation returns null.

Changing the name to another GPT entry alone would **not** solve the root path: the separate nonreturning USB branch, correct signed stock-LK loading order, exploit guarded loader, NAND safety, and device-specific function pointers all remain major unresolved issues. Do **not** overwrite or repurpose other named GPT partitions.

## 3. No bundled donor: verified build wrapper abort

The public checkout has no `tees/tee_crumpet.img`. Running *only the unmodified build wrapper's initial local-file check*:

```text
$ ./build.sh crumpet
error: no donor TEE for 'crumpet', expected tees/tee_crumpet.img
(exit status 1)
```

Nothing was compiled, signed or flashed. Donor absence is a **distribution/preparation gap**, not a proof that a compatible donor cannot exist.

## 4. Automated verification without compiling or running payloads

The new original [`audit_amonet_crumpet_boot_flow.py`](../scripts/audit_amonet_crumpet_boot_flow.py) audits upstream source C function bodies, the Crumpet device macro, platform headers, fallback USB logic and call order; it optionally reads an **existing local** Crumpet NAND image or an official Amazon OTA via bounded HTTPS Range to compare `LK_PART_NAME` against a CRC-validated GPT.

```bash
python3 scripts/audit_amonet_crumpet_boot_flow.py \
  /path/to/local/amonet-koboreru/amonet \
  --official-ota 'https://d1s31zyz7dcc2d.cloudfront.net/2025/11/28/7dba93cd-a7ab-4ba6-ba00-cfcb859d5a7a/update-kindle-crumpet-NS6571_user_6208_0012584501380.bin'
```

Example essential outputs on the pinned `2a28fd0` source:

```text
lk_partition: expdb
usb_cable_macro_defined: False
usb_fallback_always_true: True
usb_key_always_true: True
handshake_loop_no_source_exit: True
main_calls_in_expected_order: True
normal_enter_before_lk_load: True
gpt_entry_count: 18
lk_partition_in_gpt: False
gpt_contains_lk_a_and_b: True
CRUMPET DEFAULT SOURCE PATH ENTERS NONRETURNING USBDL: True
DECLARED LK_PART_NAME PRESENT IN VERIFIED GPT: False
```

Eight new **manufactured C source and NAND image tests** cover forced USBDL, a real cable callback, an unforced key detector, an exiting handshake, source-comment false positives, the absence/presence of the GPT LK name and donor-file absence. **These synthetic tests do not ship or execute upstream copyrighted firmware or ARM code.**

### Remaining root/unlock research priorities

The highest priority is **still** proving actual **Crumpet** exploitation and safe restore, neither of which this source audit supplies:

1. Obtain an independently reproducible Crumpet Preloader exploit/DA Stage-2 success report tied to a specific firmware SHA-256 and runtime RAM state.
2. Verify all fixed Amonet C function pointers and patch addresses against precisely that runtime Preloader code, rather than copying the current unchecked static values.
3. Establish actual NAND physical OOB/ECC/bad-block readback and an independent recovery route **before** considering irreversible writes or fuses.
4. Only after proving the above, determine a safe and correctly mapped LK payload storage strategy. There is no reason to attempt a live payload with the current source-level dead ends.

**Conclusion:** Neither upstream's published Crumpet source nor current public documentation establishes persistent root/unlock. We have now identified two concrete **additional** port blockers, independent of the already documented 2023+ SRAM overlap guard and DA-Stage-2 failures.

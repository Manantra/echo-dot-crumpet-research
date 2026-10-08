# Crumpet MT8167 DA2: exact Macronix NAND profile and host USB handoff fault tree

**Date:** 2026-10-09. **Target:** Amazon Echo Dot 3rd Gen Refresh / Crumpet (C78MP8, MT8167/MT8516, raw NAND), *not* Donut. **Upstream:** [MTKClient commit `cd25cf9`](https://github.com/bkerler/mtkclient/tree/cd25cf9) (2026-09-12). **Method:** static analysis of pinned stock DA binaries, original upstream host Python source and in-memory fabricated protocol responses. **No Crumpet connected, no DA uploaded or executed, no NAND touched.**

## 1. Confirmed: stock DA V5 has an exact lookup record for historical Crumpet NAND

The independent [2019 Crumpet UART log](https://github.com/jvandewiel/no-alexa/wiki/UART-logs) identifies the raw NAND chip **Macronix MX30LF4G28AD**, NAND ID **`C2 DC 90 A2 57 03`**. The [Macronix manufacturer datasheet](https://www.macronix.com/Lists/Datasheet/Attachments/8864/MX30LF4G28AD%2C%203V%2C%204Gb%2C%20v1.3.pdf) specifies 4Gb/512MiB and page/OOB/erase-block characteristics.

We inspected **the actual executable DA2 region**, excluding the last **0x100** signature-tail bytes, inside the two bundled MTKClient `HW 0x8167` DA containers:

| Pinned DA container | Full container SHA-256 | Executable DA2-body SHA-256 | Exact matching chip record? |
|---|---|---|---|
| `MTK_DA_V5.bin` | `aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f` | `b373bfcb38b5005fe71a1d1b15c0e97e8d258c8ece354221c034a545b4253d02` | **YES, one record** |
| `MTK_AllInOne_DA_mt6590.bin` | `49a1413765ed0e21fbd2c62f0e295665d0236eeb255846bd77f3329a3a86cc64` | `7d49a4b5033f4f18d69b453ce5421446f2839f325a3a7dd856daad2b4b09c3a6` | **No exact name+ID record** |

For the V5 DA2 binary loaded at virtual address `0x40000000`:

| Location / field | Verified bytes or decoded value |
|---|---|
| Device name NUL-terminated string at **file `0x4A33D`** | **`MX30LF4G28AD`** |
| Table record starts at **DA2 file `0x54164`** | `3D A3 04 40` → **pointer `0x4004A33D`**, exactly the string address |
| Record immediately after pointer (`+0x04`) | **`C2 DC 90 A2 57 03`**, matching Crumpet NAND ID, then two zero bytes |
| Record `+0x0C` | **`6`**, the ID length |
| Record `+0x10` | **`0x80000`** (numerically equal to 512MiB measured in KiB) |
| Record `+0x14` | **`0x40000`** (262144 bytes, matching a 64×4096-byte erase block) |
| Record `+0x18` | **`0x1000`** (4096 main bytes/page) |
| Record `+0x1C` | **`0x100`** (256 spare/OOB bytes/page) |

This is a **relocatable pointer + exact ID + ID-length + geometrically consistent hardware-data record**, **not** a random text match. We deliberately leave the full vendor struct's flags and other fields uninterpreted. Only one record satisfies all conditions in this pinned V5 body.

The standalone [`audit_da2_crumpet_nand_profile.py`](../scripts/audit_da2_crumpet_nand_profile.py) reproduces the exact match for the pinned DA containers using the already-existing local `Loader` folder and fails closed on a container SHA mismatch. Its eight synthetic tests distinguish: name-only, ID-only, wrong pointer, wrong ID length, changed page/OOB sizes and a truncated record. **No proprietary DA bytes are copied into this repository.**

**Interpretation for root work:** MTKClient's default `MTK_DA_V5.bin` *does* ship a DA2 device table entry for exactly the historical Crumpet NAND chip. The simplistic assertion that Stage 2 fails because there is *no NAND chip definition* is therefore contradicted by these pinned binaries. This does **not** prove DA2 correctly initializes Crumpet's NAND controller or supports every board revision. A newer unit's actual NAND ID must be verified separately and may differ. The alternate DA2's lack of this **exact** table record is not a proof that its NAND code is incapable of recognizing the chip by other means.

**Crucial ordering:** MTKClient reaches `get_nand_info()` only **after Stage-2 execution is acknowledged**. The public Crumpet failure occurs before that. It does not report a failed lookup against this NAND table; it reports **no successful DA2 handoff**.

## 2. MTKClient XFLASH Stage-2 USB failure paths: six reproducible source facts

The original [`xflash_lib.py` lines 117–158, 272–328, 952–1002, 1097–1197](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/DA/xflash/xflash_lib.py) and [`usblib.py` lines 462–535](https://github.com/bkerler/mtkclient/blob/cd25cf9/mtkclient/Library/Connection/usblib.py) establish:

1. `boot_to(addr,da,timeout=0.5)` uses `timeout` for **`time.sleep(timeout)` before the reply**, **not** the USB read timeout. Adjusting that argument cannot change how `status()` consumes endpoint data.
2. `status()` first asks `usbread(12)` for a framed header (`0xFEEEEEEF`, transport type, payload length), then `usbread(length)`. A **missing or truncated header** causes a Python `struct.error` in the `unpack("<III", hdr)` expression.
3. The `boot_to()` handler catches **any Exception** from `status()` and reports `Stage was't executed. Maybe dram issue ?.`, without retaining exception type/class, header bytes or USB transport condition in that single line. This label does **not prove** a DRAM defect.
4. `UsbClass.usbread()` uses a default **`maxtimeout=100` retry counter** and can return **empty bytes** on repeated USB timeouts or transport errors. The number 100 is **not** a 100-ms or 100-second timeout guarantee: PyUSB implementation, endpoint mode and individual read behavior matter.
5. `send_data()` loops while bytes remain and reduces `bytestowrite` **only on a truthy `usbwrite`**. It has no `break` or `else` when `usbwrite` returns `False`. Thus a persistently failing USB write can result in an **unbounded host loop**. This branch is distinct from the reported failures that *already reach* `Upload data was accepted`.
6. In `upload_da()`, **`boot_to()` must succeed before `reinit(True)`**. The high-speed USB **close/reconnect path** exists inside `reinit()`, *after* initial Stage-2 acceptance; there is no automatic reconnect on a failed initial Stage-2 status read. **Hypothesis, not observation:** if Crumpet/DA2 re-enumerates early, the host could read from a stale endpoint and print the generic DRAM error.

We have **not** captured a physical Crumpet USB re-enumeration, a DA2 crash, an actual host read exception type or runtime execution trace. The source shows the *possible* failure categories, not which one occurs on the reported units.

## 3. Offline reproduction using synthetic protocol frames

The new [`audit_xflash_stage2_transport.py`](../scripts/audit_xflash_stage2_transport.py) analyzes the unmodified upstream source **via Python AST without importing MTKClient**, and separately models the pinned frame/status branches on fabricated bytes. It detects all six source-level conditions above.

| Fabricated Stage-2 status response | Modeled upstream behavior |
|---|---|
| Empty/short 12-byte response header | `struct.error` → **generic misleading DRAM line** |
| Valid header, truncated response body | `status()` returns `-1` → **different error**, not generic DRAM line |
| Valid header + nonzero explicit status (`0xC0050005` example) | **Specific error status**, not generic DRAM line |
| Valid header + 0 or `0x434E5953` | **Accepted status** |
| Wrong magic number | `status()` returns `-1` → **not** the generic DRAM line |

These are **controlled host-side simulations**, not Crumpet hardware logs.

```bash
python3 scripts/audit_xflash_stage2_transport.py \
  /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py \
  /path/to/mtkclient/mtkclient/Library/Connection/usblib.py

python3 scripts/audit_da2_crumpet_nand_profile.py \
  /path/to/mtkclient/mtkclient/Loader

python3 -m unittest discover -s tests -q
```

Ten manufactured-source/packet tests check branch differentiation and detection of the absent abort case, the deferred reconnect and timeout argument's actual meaning. **The tests do not access a USB port or send any Download Agent.**

## Important follow-up: runtime argument magic and correctly framed XFLASH SYNC (2026-10-09)

[New original DA2 ARM/Thumb disassembly and reproducible paired-code audit](mt8167-da2-bootstrap-r0-magic-sync.md) identifies a definite software missing-response gate **before** DA2 protocol initialization: both DA1 contain `0xFE4A4D42` in their executable bodies; both DA2 begin by saving incoming `R0` at `0x40000020` and copying 88/64 bytes to BSS. `bootstrap2` checks that magic and **infinite-loops on mismatch**. On the normal branch, platform init and command setup precede a genuine **12-byte framed XFLASH header with 4-byte SYNC payload**. Hence a bare-SYNC mismatch is not a suitable generic explanation; the exact live Crumpet failed stage is still unobserved.

## 4. Additional DA2 entry/startup difference

The two MT8167 bundled DA2 bodies share the same ARM32 entry branch and bootstrapping instructions through file offset `0xF0`. At **`0x400000F4`**, their first direct next-stage call differs:

| DA2 | Decoded ARM call at 0x400000F4 |
|---|---|
| `MTK_DA_V5.bin` | `BLX 0x40000C3C` |
| `MTK_AllInOne_DA_mt6590.bin` | `BLX 0x40000A48` |

Both have `B 0x400000F8` at **`0x400000F8`**, a branch to itself if the called initializer **ever returns to that address**. It is unknown whether the called code normally returns or hands over control permanently. These are static instruction facts, **not** a proven Crumpet failure PC.

Existing [DA1↔DA2 SHA-1 pairing evidence](da1-da2-pairing-handoff-checks.md) demonstrates that each DA1 carries its *own* DA2 digest; mixing unrelated DA1/DA2 is not a supported workaround. Default DA selection already favors V5; swapping DAs blindly is **not** a justified fix.

## 5. Highest-value next evidence (read-only, owner-authorized)

An already captured *redacted* Crumpet MTKClient debug transcript and synchronized host USB event timestamps for the **same** session can discriminate:

- **DA1 and EMI:** source and SHA-256 of the exact local DA container, its patch/stock setting, source and 400-byte hash of EMI, returned Stage-1 setup call statuses.
- **DA2 transfer:** distinguish a hanging/failed `usbwrite` from a successfully acknowledged complete transfer.
- **First response after BOOT_TO:** was the **12-byte status header absent**, present but invalid magic, present with a short payload, or present with a concrete 16-/32-bit error value?
- **USB host events:** did USB `0e8d:0003` / `0e8d:2000` disappear, or did a new interface appear at exactly the status-read interval? This cannot be inferred from the generic string. Host-side passive log observation needs no NAND write.
- **Firmware compatibility:** actual flash NAND manufacturer/chip ID of that owner device, not only the public 2019 historical device.

Do not post serial numbers, MEID/SOCID, keys or entire proprietary binary dumps. **Do not attempt DA uploads, firmware writes or unrelated storage reads on irreplaceable hardware just to manufacture more diagnostic logs.**

### Priority after this update

**First determine Stage-2 USB failure category using existing evidence**, not experiment with an unsafe NAND flash. The currently selected default **DA V5 has the matching historical Macronix NAND profile**, so the strongest untested explanations are the **DA2 execution/startup sequence, DRAM access, DA1/DA2 signature/pairing state and USB endpoint handoff**; none has yet been singled out by a hardware trace.

**No functional Crumpet DA Stage-2, complete NAND readback, root or unlock has been established.**

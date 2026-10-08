# Crumpet TWRP device-tree compatibility audit: shared eMMC paths versus raw NAND

**Research date:** 2026-10-09. **Upstream source:** [R0rt1z2/twrp_device_amazon_echo-mt8167, commit `f79b0e5` (2026-08-04)](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167/tree/f79b0e5). **Device:** Amazon Echo Dot 3rd Gen Refresh `crumpet`, **not** Donut. **Method:** read-only source review versus CRC-validated logical partition names in official Amazon November-2025 `brhgptpl_0` and the independently archived 2019 Crumpet NAND excerpt.

## Result: a Crumpet build target exists, but the tree is **not evidence of working Crumpet TWRP**

The upstream tree has an actual `crumpet/BoardConfig.mk`, `crumpet/omni_crumpet.mk`, and **prebuilt ARM kernel** `crumpet/prebuilts/zImage-dtb`, SHA-256 `0ea78c5250d4c431b3856a8079d47cf0de0ff2e267b4d53536889715f26a540d`. The Crumpet target **inherits** the project-wide `BoardConfigCommon.mk`; there is no separate Crumpet-specific recovery partition table, fstab or NAND flash adapter.

The inspected repository checkout contains **no built `recovery.img` for Crumpet**. More importantly, we found **no attached real Crumpet boot/recovery log proving that this TWRP configuration boots, enumerates the expected storage, mounts filesystems, or can safely write to raw NAND**. A kernel and build recipes are not a boot-tested recovery image.

### 1. Concrete eMMC assumptions in the shared recovery files

| Shared source file | Observed code/configuration | Implication |
|---|---|---|
| [`recovery/root/etc/recovery.fstab`](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167/blob/f79b0e5/recovery/root/etc/recovery.fstab) | Defines `emmc` boot/recovery mounts; uses `/dev/block/mmcblk0boot0` for `/boot0`; other paths point to `/dev/block/platform/bootdevice/by-name/…` | **eMMC boot-partition path** is not a proven match for Crumpet's original raw NAND. Linux can expose virtual block abstractions, which must be checked on hardware. |
| [`recovery/root/init.recovery.mt8167.rc`](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167/blob/f79b0e5/recovery/root/init.recovery.mt8167.rc) | Symlinks from `/dev/block/platform/soc/11120000.mmc/` into generic `bootdevice` paths | Assumes a particular MMC controller/device-node hierarchy. No read-only Crumpet kernel log confirming it was found. |
| [`bootctrl/bootctrl_amzn.c`](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167/blob/f79b0e5/bootctrl/bootctrl_amzn.c) | Tries `/dev/block/platform/mtk-msdc.0/by-name/misc` among fallback device paths | Requires a valid misc block device. Whether a NAND-specific alias exists is unknown. |
| [`recovery/root/sbin/slot-symlinks.sh`](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167/blob/f79b0e5/recovery/root/sbin/slot-symlinks.sh) | Constructs block symlinks for `boot` and `system` slots | Assumes both requested slot names become resolvable Linux paths; actual Crumpet runtime mapping unmeasured. |

**Caution:** The Android boot-image `BOARD_KERNEL_PAGESIZE=2048` in the tree must **not be naively conflated with physical raw NAND page size**, reported separately as 4096 bytes in Crumpet boot headers. They are different layers of the boot/storage format.

### 2. Explicit recovery.fstab `by-name` references versus verified early NAND GPT

These are the source's names compared to the **18-entry early-boot NAND GPT**, CRC-validated in [our complete historical GPT study](crumpet-nand-gpt-2019-2025.md).

| Found in fstab | Labels |
|---|---|
| **Present** in early NAND GPT | `boot_a`, `boot_b`, `persist`, `userdata` |
| **Absent** from early NAND GPT | `cache`, `recovery`, `swdl`, `system_a`, `system_b` |

Five missing names are a **real early-table mismatch**, not definitive proof those paths never exist. On Android devices, `system_a`/`system_b` can be later logical volumes, virtual mappings or exposed by a completely different storage layer. `recovery` or `swdl` may be compatibility aliases, but **no such mapping was confirmed from the TWRP sources or a running Crumpet**. Conversely, merely sharing the names `boot_a` and `userdata` does not prove the corresponding Linux device nodes follow the eMMC paths in the fstab.

This is a **specific validation requirement**, not an invitation to edit `/dev/block` or force a mount on the physical device.

### 3. Static report and synthetic regression tests

The new [`scripts/audit_crumpet_twrp_storage.py`](../scripts/audit_crumpet_twrp_storage.py) checks that the local upstream `crumpet` product actually inherits the shared tree, scans `recovery.fstab` and the shell/boot-control/init source for eMMC-dependent paths, and compares *exact explicit by-name labels* with a verified NAND/GPT. It clearly **separates source-declared names from an unverified live Linux device map**.

```bash
python3 scripts/audit_crumpet_twrp_storage.py \
    /path/to/local/twrp_device_amazon_echo-mt8167 \
    --official-ota 'https://d1s31zyz7dcc2d.cloudfront.net/2025/11/28/7dba93cd-a7ab-4ba6-ba00-cfcb859d5a7a/update-kindle-crumpet-NS6571_user_6208_0012584501380.bin'
```

Alternatively specify an already acquired `--image` instead of fetching the small, manifest-hash-verified preloader component. The checker never accesses devices, mounts, flashes, generates recovery files or compiles a kernel.

Six [synthetic source/GPT tests](../tests/test_audit_crumpet_twrp_storage.py) validate missing and present labels, eMMC assumptions, missing kernel versus missing recovery image distinction, and changing source configurations. **These tests are not hardware-validation tests**.

### Priority for a usable Crumpet TWRP

An actual independent **read-only** Crumpet recovery boot trace would need to establish: signed/authorized boot of the recovery image, real device-tree/kernel support, exposed NAND or virtual-block names, storage filesystem types, and readback/recovery before writing anything. A separate proven bootloader unlock/alternate signed recovery start would also be required; the device tree alone does not supply one.

**Bottom line:** The upstream `crumpet` directory is a **build target**, not a confirmed installed or usable TWRP release. It neither supplies a persistent root exploit nor resolves raw NAND writeback risks. Do **not** flash the shared `emmc` recovery image or a Donut build to a Crumpet based solely on this source tree.

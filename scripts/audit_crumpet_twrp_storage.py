#!/usr/bin/env python3
"""Read-only comparison of Crumpet TWRP source storage paths with NAND GPT.

Analyzes the *source tree* of an external TWRP device definition and
already existing Crumpet raw NAND header or official Amazon OTA.
No build, USB/device access, filesystem mount, flash, or generated image.
A missing early-boot GPT label does not rule out a later virtual block
device or alias created by Linux.
"""
import argparse
from pathlib import Path
import re

from audit_nand_boot_gpt import inspect_image
from compare_official_preloader_payloads import extract_partition


def inspect_tree(root, gpt_image):
    root = Path(root)
    paths = {
        "board": root / "crumpet/BoardConfig.mk",
        "common": root / "BoardConfigCommon.mk",
        "target": root / "crumpet/omni_crumpet.mk",
        "fstab": root / "recovery/root/etc/recovery.fstab",
        "fstab_device": root / "recovery/root/fstab.device",
        "init": root / "recovery/root/init.recovery.mt8167.rc",
        "slot": root / "recovery/root/sbin/slot-symlinks.sh",
        "bootctrl": root / "bootctrl/bootctrl_amzn.c",
    }
    text = {key: path.read_text(encoding="utf-8") for key, path in paths.items()}
    if "include device/amazon/mt8167-echo/BoardConfigCommon.mk" not in text["board"]:
        raise ValueError("Crumpet no longer inherits common TWRP board config")
    if not re.search(r"(?m)^PRODUCT_DEVICE\s*:=\s*crumpet\s*$", text["target"]):
        raise ValueError("Not the upstream Crumpet TWRP target")

    entries = []
    for line in text["fstab"].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cols = line.split()
        if len(cols) < 3:
            raise ValueError("Malformed recovery.fstab line")
        entries.append({
            "mountpoint": cols[0], "type": cols[1],
            "paths": [v for v in cols[2:]
                      if v.startswith("/dev/block/")],
        })

    names = {p["name"] for p in inspect_image(gpt_image)["partitions"]}
    references = set()
    for entry in entries:
        for path in entry["paths"]:
            if "/by-name/" in path:
                references.add(path.split("/by-name/", 1)[1].split("/")[0])
    # The dynamic aliases may be created by userspace: report them separately.
    shell_derived = set(re.findall(
        r"\b(?:boot|system)\$\{SLOT\}", text["slot"]))
    source_mentions_emmc = {
        "kernel_boot_partition": "/dev/block/mmcblk0boot0" in text["fstab"],
        "fstab_emmc_type": any(row["type"] == "emmc" for row in entries),
        "mmc_bus_symlink": "11120000.mmc" in text["init"],
        "bootctrl_mtk_msdc": "mtk-msdc.0" in text["bootctrl"],
        "slot_script_names": bool(shell_derived),
    }
    return {
        "target": "crumpet",
        "gpt_names": sorted(names),
        "fstab_entries": entries,
        "fstab_byname_labels": sorted(references),
        "fstab_labels_absent_from_early_gpt": sorted(references - names),
        "fstab_labels_present_in_early_gpt": sorted(references & names),
        "source_emmc_features": source_mentions_emmc,
        "has_prebuilt_kernel": (root / "crumpet/prebuilts/zImage-dtb").is_file(),
        "has_built_crumpet_recovery_image":
            any((root / p).exists() for p in (
                "crumpet/recovery.img", "recovery-crumpet.img",
                "out/target/product/crumpet/recovery.img")),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("twrp_tree", type=Path, help="Local MT8167 Echo TWRP device tree")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", type=Path, help="Existing raw Crumpet boot partition image")
    source.add_argument("--official-ota", metavar="URL",
                        help="Official Amazon Crumpet OTA via bounded RAM-only Range reads")
    args = ap.parse_args()
    data = (args.image.read_bytes() if args.image else
            extract_partition(args.official_ota))
    facts = inspect_tree(args.twrp_tree, data)
    print("TWRP source target:", facts["target"])
    print("Early-boot CRC-verified GPT labels:", ", ".join(facts["gpt_names"]))
    print("TWRP recovery.fstab explicitly references these by-name labels:",
          ", ".join(facts["fstab_byname_labels"]))
    print("fstab labels ABSENT from early-boot GPT:",
          ", ".join(facts["fstab_labels_absent_from_early_gpt"]) or "none")
    print("fstab labels present in early-boot GPT:",
          ", ".join(facts["fstab_labels_present_in_early_gpt"]) or "none")
    for key, value in facts["source_emmc_features"].items():
        print(f"{key}: {value}")
    print("Source includes prebuilt Crumpet kernel:", facts["has_prebuilt_kernel"])
    print("Local tree contains recovery.img artifact:",
          facts["has_built_crumpet_recovery_image"])
    print("IMPORTANT: Missing early GPT labels do NOT disprove Linux virtual "
          "block devices. eMMC fstab assumptions require real Crumpet boot logs.")
    print("No claim of working TWRP, flash access, mount or root.")


if __name__ == "__main__":
    main()

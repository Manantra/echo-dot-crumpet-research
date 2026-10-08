"""Manufactured source fixtures for TWRP/raw-NAND partition compatibility."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_crumpet_twrp_storage import inspect_tree
from test_audit_nand_boot_gpt import synthetic_nand


def write_tree(root, emmc=True):
    files = {
        "crumpet/BoardConfig.mk":
            "include device/amazon/mt8167-echo/BoardConfigCommon.mk\n",
        "BoardConfigCommon.mk": "TARGET_BOARD_PLATFORM := mt8167\n",
        "crumpet/omni_crumpet.mk": "PRODUCT_DEVICE := crumpet\n",
        "recovery/root/etc/recovery.fstab":
            "/data ext4 /dev/block/platform/bootdevice/by-name/userdata\n"
            "/boot_a emmc /dev/block/platform/bootdevice/by-name/boot_a\n"
            "/system_a ext4 /dev/block/platform/bootdevice/by-name/system_a\n"
            "/cache ext4 /dev/block/platform/bootdevice/by-name/cache\n"
            "/lk_a emmc /dev/block/platform/bootdevice/by-name/lk_a\n"
            + ("/boot0 emmc /dev/block/mmcblk0boot0\n" if emmc else ""),
        "recovery/root/fstab.device": "/dev/block/sda /misc emmc defaults defaults\n",
        "recovery/root/init.recovery.mt8167.rc":
            ("symlink /dev/block/platform/soc/11120000.mmc "
             "/dev/block/platform/bootdevice\n" if emmc else "on early-init\n"),
        "recovery/root/sbin/slot-symlinks.sh":
            "ln -sf /dev/block/boot$" "{SLOT} /dev/block/current-boot\n",
        "bootctrl/bootctrl_amzn.c":
            ('"/dev/block/platform/mtk-msdc.0/by-name/misc"\n'
             if emmc else '"/dev/block/by-name/misc"\n'),
    }
    for subpath, value in files.items():
        file = root / subpath
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(value, encoding="utf-8")


class TwrpStorageTests(unittest.TestCase):
    def test_emmc_paths_and_missing_gpt_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root)
            facts = inspect_tree(root, synthetic_nand())
            self.assertEqual(facts["target"], "crumpet")
            self.assertEqual(facts["fstab_labels_absent_from_early_gpt"],
                             ["boot_a", "cache", "system_a", "userdata"])
            self.assertEqual(facts["fstab_labels_present_in_early_gpt"],
                             ["lk_a"])
            self.assertTrue(facts["source_emmc_features"]["kernel_boot_partition"])
            self.assertTrue(facts["source_emmc_features"]["mmc_bus_symlink"])
            self.assertFalse(facts["has_built_crumpet_recovery_image"])

    def test_kernel_presence_not_a_recovery_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root)
            kernel = root / "crumpet/prebuilts/zImage-dtb"
            kernel.parent.mkdir(exist_ok=True)
            kernel.write_bytes(b"manufactured bytes only")
            facts = inspect_tree(root, synthetic_nand())
            self.assertTrue(facts["has_prebuilt_kernel"])
            self.assertFalse(facts["has_built_crumpet_recovery_image"])

    def test_removing_emmc_assumptions_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, emmc=False)
            facts = inspect_tree(root, synthetic_nand())
            self.assertFalse(facts["source_emmc_features"]["kernel_boot_partition"])
            self.assertFalse(facts["source_emmc_features"]["mmc_bus_symlink"])
            self.assertFalse(facts["source_emmc_features"]["bootctrl_mtk_msdc"])

    def test_wrong_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root)
            (root / "crumpet/omni_crumpet.mk").write_text(
                "PRODUCT_DEVICE := donut\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Not the upstream Crumpet"):
                inspect_tree(root, synthetic_nand())

    def test_wrong_board_parent_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root)
            (root / "crumpet/BoardConfig.mk").write_text(
                "include device/amazon/donut/BoardConfig.mk\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no longer inherits"):
                inspect_tree(root, synthetic_nand())

    def test_malformed_fstab_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root)
            (root / "recovery/root/etc/recovery.fstab").write_text(
                "/data ext4\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Malformed"):
                inspect_tree(root, synthetic_nand())


if __name__ == "__main__":
    unittest.main()

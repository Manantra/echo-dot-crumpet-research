"""Static DA stage tests using synthetic image metadata and ARM vectors."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da_stage2 import inspect_directory, inspect_region
from test_audit_mtkclient_da_metadata import artificial_loader


def fake_arm_loader(path, stage2_bytes=0x300, nand=True):
    artificial_loader(path, stage2_bytes=stage2_bytes)
    raw = bytearray(path.read_bytes())
    struct.pack_into("<I", raw, 0x300, 0xEAFFFFFF)  # B from +0 to +4
    struct.pack_into("<I", raw, 0x400, 0xEA000007)  # B from +0 to +0x24
    # Minimal manufactured DA2 zeroing loop and BSS literal bounds.
    for offset, word in ((0xD4, 0xE59F0040),
                         (0xD8, 0xE59F1040),
                         (0xE0, 0xE1500001),
                         (0xE4, 0xB4802004),
                         (0x11C, 0x40000300),
                         (0x120, 0x40000400)):
        struct.pack_into("<I", raw, 0x400 + offset, word)
    if nand:
        raw[0x430:0x436] = b"[BMT]\x00"
        raw[0x440:0x44A] = b"device_nand"
    path.write_bytes(raw)


class Stage2Tests(unittest.TestCase):
    def test_stage2_arm_branch_and_markers(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            fake_arm_loader(directory / "MTK_DA_V5.bin")
            entries, hidden = inspect_directory(directory)
            self.assertEqual(len(entries), 1)
            self.assertEqual(hidden, [])
            self.assertEqual(entries[0]["stage1"]["entry"], 0x200004)
            self.assertEqual(entries[0]["stage2"]["entry"], 0x40000024)
            self.assertGreater(entries[0]["stage2"]["markers"]["Bad-block management"], 0)
            self.assertEqual(entries[0]["stage2"]["bss_interval"],
                             (0x40000300, 0x40000400))

    def test_entry_non_arm_branch_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            path = directory / "MTK_DA_V5.bin"
            fake_arm_loader(path)
            raw = bytearray(path.read_bytes())
            struct.pack_into("<I", raw, 0x400, 0x00000000)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "ARM unconditional B"):
                inspect_directory(directory)

    def test_prologue_change_disables_bss_inference(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            path = directory / "MTK_DA_V5.bin"
            fake_arm_loader(path)
            data = bytearray(path.read_bytes())
            struct.pack_into("<I", data, 0x400 + 0xD4, 0)
            path.write_bytes(data)
            entries, _ = inspect_directory(directory)
            self.assertIsNone(entries[0]["stage2"]["bss_interval"])

    def test_identical_arm_entry_does_not_imply_identical_da(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            fake_arm_loader(directory / "MTK_DA_V5.bin", stage2_bytes=0x300)
            fake_arm_loader(directory / "MTK_AllInOne_DA_dummy.bin",
                            stage2_bytes=0x200, nand=False)
            entries, hidden = inspect_directory(directory)
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0]["stage2"]["entry"],
                             entries[1]["stage2"]["entry"])
            self.assertNotEqual(entries[0]["stage2"]["region_sha256"],
                                entries[1]["stage2"]["region_sha256"])
            self.assertEqual(len(hidden), 1)


if __name__ == "__main__":
    unittest.main()

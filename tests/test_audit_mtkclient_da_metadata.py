"""Synthetic DA metadata; no MediaTek/Amazon binaries used."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_mtkclient_da_metadata import parse_loader, scan_directory


def artificial_loader(path, hw_code=0x8167, hw_subcode=0x8A00,
                      hw_version=0xCA00, stage2_bytes=0x300):
    file = bytearray(0x2000)
    struct.pack_into("<I", file, 0x68, 1)
    struct.pack_into("<HHHHHHHHHH", file, 0x6C, 0xDADA, hw_code,
                     hw_subcode, hw_version, 0, 0, 0x1000, 0, 0, 3)
    for index, (start, length, mem) in enumerate(
        [(0x200, 0x20, 0x50000000),
         (0x300, 0x40, 0x00200000),
         (0x400, stage2_bytes, 0x40000000)]
    ):
        struct.pack_into("<IIIII", file, 0x6C + 20 + index * 20,
                         start, length, mem, length, 0)
    path.write_bytes(file)


class DAMetadataTests(unittest.TestCase):
    def test_parses_synthetic_mt8167_regions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "MTK_DA_V5.bin"
            artificial_loader(path)
            matches = parse_loader(path)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["hw_code"], 0x8167)
            self.assertEqual(matches[0]["regions"][2]["address"], 0x40000000)
            self.assertEqual(matches[0]["regions"][2]["bytes"], 0x300)

    def test_filters_wrong_hardware(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "MTK_DA_V5.bin"
            artificial_loader(path, hw_code=0x8163)
            self.assertEqual(parse_loader(path), [])

    def test_duplicate_version_suppresses_second_loader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artificial_loader(root / "MTK_DA_V5.bin", stage2_bytes=0x400)
            artificial_loader(root / "MTK_AllInOne_DA_test.bin", stage2_bytes=0x200)
            matches, chosen, ignored = scan_directory(root)
            self.assertEqual(len(matches), 2)
            self.assertEqual(len(chosen), 1)
            self.assertEqual(chosen[0]["filename"], "MTK_DA_V5.bin")
            self.assertEqual(ignored[0]["filename"], "MTK_AllInOne_DA_test.bin")

    def test_matching_logic_fails_to_differentiate_subcode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artificial_loader(root / "MTK_DA_V5.bin", hw_subcode=0x8A00)
            artificial_loader(root / "MTK_AllInOne_DA_test.bin", hw_subcode=0x8B00)
            matches, chosen, ignored = scan_directory(root)
            self.assertNotEqual(matches[0]["sub_code"], matches[1]["sub_code"])
            # Reproduces the inspected upstream tautological subcode condition.
            self.assertEqual(len(chosen), 1)
            self.assertEqual(len(ignored), 1)

    def test_different_version_is_not_suppressed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artificial_loader(root / "MTK_DA_V5.bin", hw_version=0xCA00)
            artificial_loader(root / "MTK_AllInOne_DA_test.bin", hw_version=0xCB00)
            matches, chosen, ignored = scan_directory(root)
            self.assertEqual(len(matches), 2)
            self.assertEqual(len(chosen), 2)
            self.assertEqual(len(ignored), 0)

    def test_missing_loader_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "existing local"):
                scan_directory(Path(temp) / "does-not-exist")


if __name__ == "__main__":
    unittest.main()

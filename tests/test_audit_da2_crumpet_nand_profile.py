"""Synthetic name-pointer + ID table fixtures; original DA binaries NOT included."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da2_crumpet_nand_profile import (
    MODEL, ID, LOAD_BASE, find_chip_profiles,
)


def artificial_da2(name=True, id=True, size=0x2000, page=4096, oob=256,
                   id_length=6):
    data = bytearray(size)
    name_at = 0x600
    table_at = 0x1400
    if name:
        data[name_at:name_at + len(MODEL)] = MODEL
    struct.pack_into("<I", data, table_at, LOAD_BASE + name_at)
    if id:
        data[table_at + 4:table_at + 4 + len(ID)] = ID
    struct.pack_into("<I", data, table_at + 0xC, id_length)
    struct.pack_into("<IIII", data, table_at + 0x10,
                     0x80000, 0x40000, page, oob)
    return bytes(data)


class ChipTableTests(unittest.TestCase):
    def test_complete_model_pointer_id_page_and_oob_match(self):
        matches = find_chip_profiles(artificial_da2())
        self.assertEqual(len(matches), 1)
        row = matches[0]
        self.assertEqual(row["name_address"], LOAD_BASE + 0x600)
        self.assertEqual(row["record_offset"], 0x1400)
        self.assertEqual(row["nand_id"], ID.hex(" "))
        self.assertEqual(row["id_length"], 6)
        self.assertEqual(row["field_0x10_raw"], 0x80000)
        self.assertEqual(row["field_0x14_raw"], 0x40000)
        self.assertTrue(row["page_geometry_matches_reported_chip"])

    def test_name_only_not_enough(self):
        self.assertEqual(find_chip_profiles(artificial_da2(id=False)), [])

    def test_id_only_not_enough(self):
        self.assertEqual(find_chip_profiles(artificial_da2(name=False)), [])

    def test_wrong_id_length_rejected(self):
        self.assertEqual(find_chip_profiles(artificial_da2(id_length=5)), [])

    def test_wrong_page_size_reports_mismatch_not_false_id(self):
        matches = find_chip_profiles(artificial_da2(page=2048))
        self.assertEqual(len(matches), 1)
        self.assertFalse(matches[0]["page_geometry_matches_reported_chip"])

    def test_wrong_oob_reports_mismatch(self):
        matches = find_chip_profiles(artificial_da2(oob=64))
        self.assertEqual(len(matches), 1)
        self.assertFalse(matches[0]["page_geometry_matches_reported_chip"])

    def test_wrong_table_pointer_rejected(self):
        b = bytearray(artificial_da2())
        struct.pack_into("<I", b, 0x1400, LOAD_BASE + 0x900)
        self.assertEqual(find_chip_profiles(bytes(b)), [])

    def test_no_full_struct_at_end(self):
        b = bytearray(artificial_da2(size=0x1500))
        # Only model name and pointer+ID but no complete ID-length etc.
        b = b[:0x1400 + 8]
        self.assertEqual(find_chip_profiles(bytes(b)), [])


if __name__ == "__main__":
    unittest.main()

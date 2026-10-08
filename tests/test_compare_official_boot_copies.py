"""Manufactured NAND boot-copy comparisons; no real Amazon images or USB."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compare_official_boot_copies import compare_copies

BASE = b"\x00" * 64 + b"MMM\x01" + b"\x99" * 100


class BootCopiesTests(unittest.TestCase):
    def test_same_core_four_copies_have_no_suffix_changes(self):
        copies = []
        for i in range(4):
            payload = bytearray(BASE)
            payload[12:16] = i.to_bytes(4, "little")
            copies.append(bytes(payload))
        result = compare_copies(copies)
        self.assertEqual(len(result), 4)
        self.assertEqual(result[0][2], [])
        for i in range(1, 4):
            self.assertEqual(result[i][1]["suffix_changed_bytes"], 0)
            self.assertEqual(result[i][2], [12])

    def test_modified_gfh_payload_is_explicit(self):
        copies = [BASE, BASE, BASE, bytearray(BASE)]
        copies[3][-1] ^= 1
        result = compare_copies([bytes(v) for v in copies])
        self.assertEqual(result[3][1]["suffix_changed_bytes"], 1)

    def test_wrong_number_of_partitions_rejected(self):
        with self.assertRaisesRegex(ValueError, "Four"):
            compare_copies([BASE] * 3)


if __name__ == "__main__":
    unittest.main()

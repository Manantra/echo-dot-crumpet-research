"""Synthetic, vendor-binary-free contract regressions for DA1 state initialization."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da1_state_initializers import INITIALIZERS, validate_offsets, audit_defaults

class DA1StateInitializerTests(unittest.TestCase):
    def test_stock_profiles_described(self):
        self.assertEqual(set(INITIALIZERS), {"MTK_DA_V5.bin", "MTK_AllInOne_DA_mt6590.bin"})

    def test_v5_write_count_and_bounds(self):
        self.assertEqual(validate_offsets(INITIALIZERS["MTK_DA_V5.bin"]["writes"], 56), 11)

    def test_alt_write_count_and_bounds(self):
        self.assertEqual(validate_offsets(INITIALIZERS["MTK_AllInOne_DA_mt6590.bin"]["writes"], 32), 7)

    def test_v5_revision_count(self):
        self.assertEqual(validate_offsets(INITIALIZERS["MTK_DA_V5.bin"]["revisions"], 56), 3)

    def test_alt_revision_count(self):
        self.assertEqual(validate_offsets(INITIALIZERS["MTK_AllInOne_DA_mt6590.bin"]["revisions"], 32), 2)

    def test_overflow_rejected(self):
        with self.assertRaises(ValueError):
            validate_offsets([(0x10, "str", "", 32)], 32)

    def test_misaligned_rejected(self):
        with self.assertRaises(ValueError):
            validate_offsets([(0x10, "str", "", 3)], 56)

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            validate_offsets([(0x10, "str", "", -4)], 56)

    def test_duplicate_site_rejected(self):
        with self.assertRaises(ValueError):
            validate_offsets([(0x10, "str", "", 0), (0x10, "str", "", 4)], 56)

    def test_unknown_loader_rejected(self):
        with self.assertRaises(ValueError):
            audit_defaults("untrusted.bin", b"")

if __name__ == "__main__":
    unittest.main()

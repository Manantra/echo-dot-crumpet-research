"""Pure arithmetic tests; no raw dump, device or proprietary content required."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_crumpet_raw_nand_dump_size import (
    BLOCK_COUNT, PAGES_PER_BLOCK, TOTAL_PAGES,
    DATA_ONLY_SIZE, DATA_PLUS_OOB_SIZE, RAW_PAGE_BYTES,
    HISTORIC_BBT_PAGES, describe_size,
)


class GeometryTests(unittest.TestCase):
    def test_chip_has_131072_physical_pages(self):
        self.assertEqual(BLOCK_COUNT * PAGES_PER_BLOCK, 131072)
        self.assertEqual(TOTAL_PAGES, 131072)

    def test_expected_interleaved_oob_dump_bytes(self):
        self.assertEqual(DATA_PLUS_OOB_SIZE, 570425344)
        self.assertEqual(RAW_PAGE_BYTES, 4352)
        self.assertEqual(describe_size(DATA_PLUS_OOB_SIZE)["classification"],
                         "exact_data_plus_oob")

    def test_expected_data_only_dump_bytes(self):
        self.assertEqual(DATA_ONLY_SIZE, 536870912)
        self.assertEqual(describe_size(DATA_ONLY_SIZE)["classification"],
                         "exact_data_only")

    def test_partial_oob_dump_is_not_complete(self):
        data = describe_size(DATA_PLUS_OOB_SIZE - RAW_PAGE_BYTES)
        self.assertEqual(data["classification"], "other_or_partial")
        self.assertTrue(data["could_be_interleaved_raw_page_aligned"])

    def test_partial_data_dump_is_not_complete(self):
        data = describe_size(DATA_ONLY_SIZE - 4096)
        self.assertEqual(data["classification"], "other_or_partial")
        self.assertTrue(data["could_be_data_page_aligned"])

    def test_historical_bbt_copies_are_last_two_blocks(self):
        self.assertEqual(HISTORIC_BBT_PAGES,
                         (2047 * PAGES_PER_BLOCK, 2046 * PAGES_PER_BLOCK))

    def test_size_never_claims_ecc_or_recovery_verified(self):
        for size in (0, DATA_ONLY_SIZE, DATA_PLUS_OOB_SIZE):
            data = describe_size(size)
            self.assertFalse(data["ecc_validated"])
            self.assertFalse(data["bbt_validated"])
            self.assertFalse(data["has_oob_proven"])

    def test_negative_file_size_rejected(self):
        with self.assertRaises(ValueError):
            describe_size(-1)


if __name__ == "__main__":
    unittest.main()

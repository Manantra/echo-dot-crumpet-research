"""Synthetic regression tests; no vendor dumps, device or USB required."""
import io
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compare_crumpet_raw_nand_captures import (
    RAW_PAGE_BYTES, FOUR_CHUNK_MAIN, FOUR_CHUNK_SIZE,
    compare_files, compare_streams, classify_differences, validate_size
)
from check_crumpet_raw_nand_dump_size import DATA_PLUS_OOB_SIZE


def page(fill=0):
    return bytes([fill]) * RAW_PAGE_BYTES


class DualCaptureTests(unittest.TestCase):
    def test_full_historical_size_accepted(self):
        self.assertEqual(validate_size(DATA_PLUS_OOB_SIZE, False), 131072)

    def test_partial_rejected_by_default(self):
        with self.assertRaises(ValueError):
            validate_size(RAW_PAGE_BYTES, False)

    def test_partial_explicit(self):
        self.assertEqual(validate_size(2 * RAW_PAGE_BYTES, True), 2)

    def test_short_last_page_fails_even_in_partial_mode(self):
        with self.assertRaises(ValueError):
            validate_size(RAW_PAGE_BYTES + 1, True)

    def test_zero_bytes_rejected(self):
        with self.assertRaises(ValueError):
            validate_size(0, True)

    def test_over_capacity_rejected(self):
        with self.assertRaises(ValueError):
            validate_size(DATA_PLUS_OOB_SIZE + RAW_PAGE_BYTES, True)

    def test_identical_pages(self):
        data = page(2) + page(3)
        r = compare_streams(io.BytesIO(data), io.BytesIO(data), len(data),
                            allow_partial=True)
        self.assertTrue(r["raw_bytes_match_exactly"])
        self.assertEqual(r["different_pages"], 0)
        self.assertFalse(r["safe_to_restore"])
        self.assertFalse(r["ecc_validated"])
        self.assertEqual(r["scope"], "partial_only")

    def test_opaque_does_not_assume_main_oob(self):
        a = page()
        b = bytearray(a)
        b[-1] = 1
        r = compare_streams(io.BytesIO(a), io.BytesIO(b), len(a), allow_partial=True)
        self.assertEqual(r["different_pages"], 1)
        self.assertEqual(r["auxiliary_only_differences"], 0)
        self.assertEqual(r["layout_assumption"], "opaque")

    def test_interleaved_aux_only(self):
        a = page()
        b = bytearray(a)
        b[FOUR_CHUNK_MAIN] = 1
        self.assertEqual(classify_differences(a, b, "interleaved-four"), (False, True))
        r = compare_streams(io.BytesIO(a), io.BytesIO(b), len(a),
                            "interleaved-four", True)
        self.assertEqual(r["auxiliary_only_differences"], 1)
        self.assertFalse(r["oob_structure_validated"])

    def test_interleaved_main_only_second_chunk(self):
        a = page()
        b = bytearray(a)
        b[FOUR_CHUNK_SIZE + 1] = 1
        self.assertEqual(classify_differences(a, b, "interleaved-four"), (True, False))

    def test_contiguous_layout_differs_from_interleaved(self):
        a = page()
        b = bytearray(a)
        b[FOUR_CHUNK_MAIN] = 1
        self.assertEqual(classify_differences(a, b, "contiguous"), (True, False))
        self.assertEqual(classify_differences(a, b, "interleaved-four"), (False, True))

    def test_mixed_difference(self):
        a = page()
        b = bytearray(a)
        b[3] = 1
        b[-1] = 2
        self.assertEqual(classify_differences(a, b, "interleaved-four"), (True, True))

    def test_page_indices_and_distinct_erase_blocks(self):
        data = page() * 65
        new = bytearray(data)
        new[64 * RAW_PAGE_BYTES] = 3
        new[5 * RAW_PAGE_BYTES] = 4
        r = compare_streams(io.BytesIO(data), io.BytesIO(new), len(data),
                            allow_partial=True)
        self.assertEqual(r["different_pages"], 2)
        self.assertEqual(r["different_erase_blocks"], 2)
        self.assertEqual(r["first_different_pages"], [5, 64])

    def test_premature_eof_rejected(self):
        a = page()
        with self.assertRaises(ValueError):
            compare_streams(io.BytesIO(a), io.BytesIO(b""), len(a), allow_partial=True)

    def test_unexpected_extra_data_rejected(self):
        with self.assertRaises(ValueError):
            compare_streams(io.BytesIO(page() + b"x"), io.BytesIO(page()),
                            RAW_PAGE_BYTES, allow_partial=True)

    def test_two_real_small_files(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "one.bin"
            q = Path(td) / "two.bin"
            p.write_bytes(page(2))
            q.write_bytes(page(2))
            r = compare_files(p, q, allow_partial=True)
            self.assertTrue(r["raw_bytes_match_exactly"])
            self.assertFalse(r["safe_to_restore"])

    def test_same_file_or_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "one.bin"
            q = Path(td) / "two.bin"
            p.write_bytes(page())
            q.hardlink_to(p)
            with self.assertRaises(ValueError):
                compare_files(p, q, allow_partial=True)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "one.bin"
            q = Path(td) / "two.bin"
            p.write_bytes(page())
            q.symlink_to(p)
            with self.assertRaises(ValueError):
                compare_files(p, q, allow_partial=True)


if __name__ == "__main__":
    unittest.main()

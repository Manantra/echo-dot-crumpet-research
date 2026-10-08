"""Purely synthetic tests: GFH-anchored preloader byte-identity classification."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compare_official_preloader_payloads import GFH_MARKER, summarize_pair


def manufactured(prefix=b"\x00" * 128, suffix=b"\x01" * 64):
    return prefix + GFH_MARKER + suffix


class PreloaderComparisonTests(unittest.TestCase):
    def test_equal_images_have_no_changes(self):
        image = manufactured()
        stats = summarize_pair(image, image)
        self.assertEqual(stats["prefix_changed_bytes"], 0)
        self.assertEqual(stats["suffix_changed_bytes"], 0)
        self.assertEqual(stats["gfh_offset"], 128)
        self.assertIsNone(stats["first_difference"])

    def test_prefix_only_difference_does_not_imply_image_change(self):
        first = manufactured()
        second = bytearray(first)
        second[23] ^= 0x12
        stats = summarize_pair(first, bytes(second))
        self.assertNotEqual(stats["full_sha256_a"], stats["full_sha256_b"])
        self.assertEqual(stats["gfh_suffix_sha256_a"], stats["gfh_suffix_sha256_b"])
        self.assertEqual(stats["prefix_changed_bytes"], 1)
        self.assertEqual(stats["suffix_changed_bytes"], 0)
        self.assertEqual(stats["first_difference"], 23)

    def test_gfh_image_change_is_detected(self):
        first = manufactured()
        second = bytearray(first)
        second[-1] ^= 3
        stats = summarize_pair(first, bytes(second))
        self.assertEqual(stats["prefix_changed_bytes"], 0)
        self.assertEqual(stats["suffix_changed_bytes"], 1)
        self.assertNotEqual(stats["gfh_suffix_sha256_a"],
                            stats["gfh_suffix_sha256_b"])

    def test_different_image_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "different-sized"):
            summarize_pair(manufactured(), manufactured() + b"\x00")

    def test_missing_gfh_rejected(self):
        with self.assertRaisesRegex(ValueError, "GFH"):
            summarize_pair(b"\x00" * 100, b"\x00" * 100)

    def test_gfh_at_different_offsets_rejected(self):
        first = manufactured(b"\x00" * 128)
        second = manufactured(b"\x00" * 127, b"\x01" * 65)
        with self.assertRaisesRegex(ValueError, "GFH"):
            summarize_pair(first, second)


if __name__ == "__main__":
    unittest.main()

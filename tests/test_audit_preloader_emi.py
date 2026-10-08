"""Tests with manufactured MediaTek metadata; no proprietary firmware needed."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_preloader_emi import GFH, BLOADER, inspect


def fake_preloader():
    prefix = b"\x00" * 0x200
    image = bytearray(0x700)
    image[:8] = GFH
    struct.pack_into("<I", image, 0x20, len(image))
    struct.pack_into("<I", image, 0x2c, 0x100)
    # Manifest signature is the last 0x100 bytes; EMI block is at the
    # trailing end of the unsigned body in the same format MTKClient uses.
    emi = BLOADER + b"28" + b"\x00" * (400 - len(BLOADER) - 2)
    body_end = 0x600
    image[body_end - 4 - len(emi):body_end - 4] = emi
    struct.pack_into("<I", image, body_end - 4, len(emi))
    return prefix + bytes(image)


class EMITests(unittest.TestCase):
    def test_extracted_length_and_version(self):
        meta = inspect(fake_preloader())
        self.assertEqual(meta["version"], "28")
        self.assertEqual(meta["length"], 400)
        self.assertEqual(len(meta["sha256"]), 64)

    def test_missing_gfh_rejected(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            inspect(b"\x00" * 0x900)

    def test_corrupt_footer_rejected(self):
        b = bytearray(fake_preloader())
        struct.pack_into("<I", b, 0x200 + 0x600 - 4, 0xFFFFF)
        with self.assertRaisesRegex(ValueError, "Unreasonable"):
            inspect(bytes(b))

    def test_non_mtk_emi_marker_rejected(self):
        b = bytearray(fake_preloader())
        index = b.index(BLOADER)
        b[index] ^= 1
        with self.assertRaisesRegex(ValueError, "missing"):
            inspect(bytes(b))

    def test_invalid_version_rejected(self):
        b = bytearray(fake_preloader())
        index = b.index(BLOADER) + len(BLOADER)
        b[index:index + 2] = b"XX"
        with self.assertRaisesRegex(ValueError, "Invalid"):
            inspect(bytes(b))


if __name__ == "__main__":
    unittest.main()

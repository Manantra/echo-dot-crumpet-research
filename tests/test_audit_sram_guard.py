"""Purely synthetic checks of PC-relative protected SRAM boundaries."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_sram_guard as sram
from test_disassemble_preloader import sample_image


def synthetic_guarded_image():
    image = bytearray(sample_image())
    image.extend(b"\x00" * (0x2D000 - len(image)))
    image[0x2A000:0x2A03B] = (
        b"load range overlap text region\x00"
        b"load range overlap bss region\x00").ljust(0x3B, b"\x00")

    # Assign known fake bounds to a valid synthetic FILE_INFO and an ARM entry.
    start = 0x200D00
    entry = 0x500
    values = {
        "text_start": (0x225118, 0x00201000),
        "text_end": (0x22511C, 0x002254CC),
        "bss_start": (0x225120, 0x00102180),
        "bss_end": (0x225124, 0x00109DAC),
    }
    for name, (pointer, boundary) in values.items():
        literal_vma, add_vma = sram.PC_RELATIVE_BOUNDS[name]
        struct.pack_into("<i", image, entry + literal_vma - start,
                         pointer - (add_vma + 4))
        struct.pack_into("<I", image, entry + pointer - start, boundary)
    return bytes(image)


class SramAuditTests(unittest.TestCase):
    def test_extract_synthetic_ranges(self):
        regions = sram.extract_protected_ranges(synthetic_guarded_image())
        self.assertEqual(regions["text"], (0x201000, 0x2254CC))
        self.assertEqual(regions["bss"], (0x102180, 0x109DAC))

    def test_attack_target_intersects_bss(self):
        ranges = sram.extract_protected_ranges(synthetic_guarded_image())
        self.assertEqual(sram.crafted_subimage_size(0x1086EC), 0x108804)
        self.assertTrue(ranges["bss"][0] <= 0x1086EC < ranges["bss"][1])
        self.assertTrue(sram.overlap_with((0, 0x108804), ranges["bss"]))
        self.assertFalse(sram.overlap_with((0, 0x108804), ranges["text"]))

    def test_reject_old_image_without_new_diagnostics(self):
        with self.assertRaisesRegex(ValueError, "expected newer"):
            sram.extract_protected_ranges(sample_image())

    def test_no_overlap_and_invalid_ranges(self):
        self.assertFalse(sram.overlap_with((0, 10), (10, 20)))
        self.assertTrue(sram.overlap_with((1, 11), (10, 20)))
        with self.assertRaises(ValueError):
            sram.overlap_with((-1, 0), (0, 1))


if __name__ == "__main__":
    unittest.main()

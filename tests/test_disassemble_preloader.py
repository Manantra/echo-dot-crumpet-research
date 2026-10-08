"""Synthetic ARM entry and address-map tests, no firmware required."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import disassemble_preloader as loader


def sample_image():
    data = bytearray(0x2000)
    header = 0x200
    data[header:header + 4] = b"MMM\x01"
    struct.pack_into("<I", data, header + 4, 0x38)
    data[header + 8:header + 18] = b"FILE_INFO\x00"
    struct.pack_into("<I", data, header + 0x1c, 0x200d00)
    entry = header + 0x300
    data[entry + 4:entry + 8] = b"\x03\x00\x00\xea"
    data[entry + 0x24:entry + 0x26] = b"\x70\x47"  # Thumb bx lr
    return bytes(data)


class ImageMappingTests(unittest.TestCase):
    def test_entry_and_address(self):
        data = sample_image()
        self.assertEqual(loader.locate_image(data), (0x500, 0x200d00))
        self.assertEqual(loader.address_to_offset(data, 0x200d24, 2), 0x524)

    def test_reject_malformed_branch(self):
        data = bytearray(sample_image())
        data[0x504] = 0
        with self.assertRaisesRegex(ValueError, "validated"):
            loader.locate_image(bytes(data))

    def test_reject_out_of_bounds(self):
        data = sample_image()
        with self.assertRaisesRegex(ValueError, "below"):
            loader.address_to_offset(data, 0x1000)
        with self.assertRaisesRegex(ValueError, "not present"):
            loader.address_to_offset(data, 0x202d00)

    def test_thumb_sample_if_capstone_available(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("Optional Capstone dependency is not installed")
        instructions = loader.disassemble(sample_image(), 0x200d24, 2)
        self.assertEqual(instructions[0][2], "bx")
        self.assertEqual(instructions[0][3], "lr")


if __name__ == "__main__":
    unittest.main()

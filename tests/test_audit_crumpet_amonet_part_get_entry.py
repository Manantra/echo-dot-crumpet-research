"""Manufactured firmware-only Thumb-2 boundary tests; no copyrighted code shipped."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_crumpet_amonet_part_get_entry import (
    KNOWN, parse_part_get_address, thumb_boundary, inspect_verified_image,
)
from disassemble_preloader import address_to_offset


def manufactured_image():
    data = bytearray(0x2D000)
    base = 0x8000
    data[base:base + 4] = b"MMM\x01"
    struct.pack_into("<I", data, base + 4, 0x38)
    data[base + 8:base + 18] = b"FILE_INFO\x00"
    struct.pack_into("<I", data, base + 0x1c, 0x200D00)
    # Required official-image structural check: A32 branch at entry +4.
    data[base + 0x304:base + 0x308] = bytes.fromhex("030000ea")
    return data


def put(data, address, code):
    offset = address_to_offset(data, address, len(code))
    data[offset:offset + len(code)] = code


class ThumbEntryTests(unittest.TestCase):
    HEADER = '#define PART_GET_ADDR 0x0020F250\n'

    def test_address_is_parsed_from_original_style_header(self):
        self.assertEqual(parse_part_get_address(self.HEADER), 0x20F250)

    def test_duplicate_macro_fails(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            parse_part_get_address(self.HEADER * 2)

    def test_2025_target_is_second_halfword(self):
        data = manufactured_image()
        # A manufactured Thumb stream matching the observed instruction
        # widths at VMA 0x20F24A: 16-bit LDR; 16-bit MOV; 32-bit MOV.W.
        put(data, 0x20F24A, bytes.fromhex("206829464ff42062"))
        result = thumb_boundary(bytes(data), 0x20F250, 0x20F24A,
                                bytes.fromhex("20682946"))
        self.assertEqual(result["relation"], "middle_of_thumb2_instruction")
        self.assertEqual(result["containing_vma"], 0x20F24E)
        self.assertEqual(result["containing_size"], 4)
        self.assertEqual(result["containing_mnemonic"], "mov.w")

    def test_2022_target_is_second_halfword(self):
        data = manufactured_image()
        put(data, 0x20F248, bytes.fromhex("e3e0daf8003016f50076"))
        result = thumb_boundary(bytes(data), 0x20F250, 0x20F248,
                                bytes.fromhex("e3e0daf8"))
        self.assertEqual(result["relation"], "middle_of_thumb2_instruction")
        self.assertEqual(result["containing_vma"], 0x20F24E)
        self.assertEqual(result["containing_size"], 4)

    def test_archived_2019_target_also_inside_thumb2(self):
        data = manufactured_image()
        # 2019: 16-bit cmp, 32-bit conditional branch, 32-bit LDR.W.
        put(data, 0x20F248, bytes.fromhex("9c4200f0ad80d0f89c30"))
        result = thumb_boundary(bytes(data), 0x20F250, 0x20F248,
                                bytes.fromhex("9c4200f0"))
        self.assertEqual(result["relation"], "middle_of_thumb2_instruction")
        self.assertEqual(result["containing_vma"], 0x20F24E)
        self.assertEqual(result["containing_size"], 4)
        self.assertEqual(result["containing_mnemonic"], "ldr.w")

    def test_2021_same_address_is_an_instruction_boundary(self):
        data = manufactured_image()
        put(data, 0x20F248, bytes.fromhex("06f012fbdaf8003003f5cd23"))
        result = thumb_boundary(bytes(data), 0x20F250, 0x20F248,
                                bytes.fromhex("06f012fb"))
        self.assertEqual(result["relation"],
                         "instruction_boundary_not_function_proof")
        self.assertEqual(result["containing_vma"], 0x20F250)

    def test_anchor_byte_mismatch_rejected(self):
        data = manufactured_image()
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            thumb_boundary(bytes(data), 0x20F250, 0x20F24A,
                           bytes.fromhex("20682946"))

    def test_target_before_anchor_rejected(self):
        data = manufactured_image()
        with self.assertRaisesRegex(ValueError, "outside bounded"):
            thumb_boundary(bytes(data), 0x20F244, 0x20F24A, b"\x00")

    def test_unknown_full_image_fingerprint_rejected(self):
        self.assertEqual(len(KNOWN), 4)
        with self.assertRaisesRegex(ValueError, "Unknown full partition"):
            inspect_verified_image(self.HEADER, bytes(manufactured_image()))


if __name__ == "__main__":
    unittest.main()

"""Synthetic Crumpet ARM bootstrap tests. Never include original firmware bytes."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_preloader_bootstrap import REQUIRED_OPCODES, decode_startup


def synthetic_bootstrap(gfh=0x8000, bss_start=0x102180,
                        bss_end=0x109DAC, thumb=0x20E40D):
    data = bytearray(max(gfh + 0x400, 0x2D000))
    data[gfh:gfh + 4] = b"MMM\x01"
    struct.pack_into("<I", data, gfh + 4, 0x38)
    data[gfh + 8:gfh + 18] = b"FILE_INFO\x00"
    struct.pack_into("<I", data, gfh + 0x1C, 0x00200D00)
    entry = gfh + 0x300
    for offset, opcode in REQUIRED_OPCODES.items():
        struct.pack_into("<I", data, entry + offset, opcode)
    struct.pack_into("<IIII", data, entry + 8, bss_start, bss_end,
                     0x103050, 0x222998)
    struct.pack_into("<III", data, entry + 0x144, 0x201000,
                     0xDEADBEFF, 0xE51FF004)
    struct.pack_into("<I", data, entry + 0x150, thumb)
    return data


class StartupTests(unittest.TestCase):
    def test_2025_synthetic_bootstrap(self):
        data = synthetic_bootstrap()
        res = decode_startup(bytes(data))
        self.assertEqual(res["encoded_base"], 0x200D00)
        self.assertEqual(res["bss_start"], 0x102180)
        self.assertEqual(res["bss_end_exclusive"], 0x109DAC)
        self.assertEqual(res["debug_marker"], 0xDEADBEFF)
        self.assertEqual(res["thumb_pointer"], 0x20E40D)
        self.assertEqual(res["thumb_stored_offset"], 0x15A0C)

    def test_2019_legacy_header_mapping(self):
        data = synthetic_bootstrap(gfh=0x6000, bss_end=0x1097FC,
                                   thumb=0x20E34D)
        res = decode_startup(bytes(data))
        self.assertEqual(res["entry_offset"], 0x6300)
        self.assertEqual(res["thumb_stored_offset"], 0x1394C)
        self.assertEqual(res["bss_end_exclusive"], 0x1097FC)

    def test_bad_arm_loop_fails_closed(self):
        data = synthetic_bootstrap()
        struct.pack_into("<I", data, 0x8300 + 0xC4, 0xE1A00000)
        with self.assertRaisesRegex(ValueError, "opcode mismatch"):
            decode_startup(bytes(data))

    def test_invalid_bss_rejected(self):
        with self.assertRaisesRegex(ValueError, "BSS"):
            decode_startup(bytes(synthetic_bootstrap(
                bss_start=0x109DAC, bss_end=0x102180)))

    def test_misaligned_bss_rejected(self):
        with self.assertRaisesRegex(ValueError, "BSS"):
            decode_startup(bytes(synthetic_bootstrap(
                bss_start=0x102181)))

    def test_even_thumb_pointer_rejected(self):
        with self.assertRaisesRegex(ValueError, "not odd"):
            decode_startup(bytes(synthetic_bootstrap(thumb=0x20E40C)))

    def test_out_of_bounds_thumb_target_rejected(self):
        with self.assertRaisesRegex(ValueError, "not present"):
            decode_startup(bytes(synthetic_bootstrap(thumb=0x250001)))

    def test_missing_gfh_rejected(self):
        data = synthetic_bootstrap()
        data[0x8000] = 0
        with self.assertRaisesRegex(ValueError, "No validated"):
            decode_startup(bytes(data))


if __name__ == "__main__":
    unittest.main()

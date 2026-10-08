"""Synthetic, proprietary-firmware-free tests for the new guard-chain inspector."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_guard_chain as checker


def thumb_bl(source, target):
    """Encode standard ARMv7 Thumb-2 BL from ISA bit fields."""
    delta = target - source - 4
    if delta % 2 or not -(1 << 24) <= delta < (1 << 24):
        raise ValueError("Unencodable BL delta")
    value = delta & 0x1ffffff
    sign = (value >> 24) & 1
    i1, i2 = (value >> 23) & 1, (value >> 22) & 1
    j1, j2 = 1 ^ sign ^ i1, 1 ^ sign ^ i2
    hw1 = 0xf000 | (sign << 10) | ((value >> 12) & 0x3ff)
    hw2 = 0xd000 | (j1 << 13) | (j2 << 11) | ((value >> 1) & 0x7ff)
    return struct.pack("<HH", hw1, hw2)


def fake_image():
    result = bytearray(0x2d000)
    result[0x8000:0x8004] = b"MMM\x01"
    struct.pack_into("<I", result, 0x8004, 0x38)
    result[0x8008:0x8012] = b"FILE_INFO\x00"
    struct.pack_into("<I", result, 0x801c, 0x200d00)
    result[0x8304:0x8308] = b"\x03\x00\x00\xea"

    def off(vma):
        return 0x8300 + vma - 0x200d00

    # ARM Thumb high-register ADD instructions with PC operand.
    for index, (label, addaddr, literal) in enumerate(checker.REGION_REFERENCES):
        reg = 2 if index % 2 == 0 else 3
        struct.pack_into("<H", result, off(addaddr), 0x4400 | (15 << 3) | reg)
        dst = 0x225118 + index * 4
        struct.pack_into("<I", result, off(literal), dst - addaddr - 4)
        value = [0x201000, 0x2254cc, 0x102180, 0x109dac][index]
        struct.pack_into("<I", result, off(dst), value)

    for label, src, dst in checker.CALL_CHAIN:
        result[off(src):off(src) + 4] = thumb_bl(src, dst)
    # Thumb CBNZ r0 to branch target 0x20f4a6.
    cbaddr, dest = 0x20f494, 0x20f4a6
    imm = dest - cbaddr - 4
    opcode = 0xb900 | (((imm >> 6) & 1) << 9) | (((imm >> 1) & 0x1f) << 3)
    struct.pack_into("<H", result, off(cbaddr), opcode)
    return bytes(result)


class GuardTests(unittest.TestCase):
    def setUp(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("Optional Capstone dependency not installed")

    def test_static_guard_chain_on_synthetic_image(self):
        bounds, calls = checker.inspect(fake_image())
        self.assertEqual(bounds["bss_start"], 0x102180)
        self.assertEqual(bounds["bss_end"], 0x109dac)
        self.assertTrue(bounds["bss_start"] <= checker.UPSTREAM_BDEV_ADDR <
                        bounds["bss_end"])
        self.assertEqual(len(calls), len(checker.CALL_CHAIN))

    def test_rejects_modified_branch_destination(self):
        b = bytearray(fake_image())
        position = 0x8300 + 0x20f490 - 0x200d00
        b[position:position + 4] = thumb_bl(0x20f490, 0x20f1a2)
        with self.assertRaisesRegex(ValueError, "Call-chain mismatch"):
            checker.inspect(bytes(b))

    def test_rejects_modified_bounds(self):
        b = bytearray(fake_image())
        position = 0x8300 + 0x225124 - 0x200d00
        struct.pack_into("<I", b, position, 0)
        with self.assertRaisesRegex(ValueError, "Unreasonable bss"):
            checker.inspect(bytes(b))


if __name__ == "__main__":
    unittest.main()

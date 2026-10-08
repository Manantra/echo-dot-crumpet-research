"""Firmware-free tests for validated vendor LK Fastboot unlock control flow."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_lk_unlock as lk


def encode_thumb_bl(site, target):
    """Thumb BL encoder used only to create artificial unit-test data."""
    delta = target - site - 4
    if delta % 2 or not -(1 << 24) <= delta < (1 << 24):
        raise ValueError("BL is out of range or unaligned")
    v = delta & 0x1FFFFFF
    s, i1, i2 = (v >> 24) & 1, (v >> 23) & 1, (v >> 22) & 1
    j1, j2 = 1 ^ s ^ i1, 1 ^ s ^ i2
    return struct.pack("<HH", 0xF000 | (s << 10) | ((v >> 12) & 0x3FF),
                       0xD000 | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7FF))


def synthetic_lk():
    b = bytearray(lk.EXPECTED_BYTES)
    for name, (offset, marker) in lk.STRINGS.items():
        b[offset:offset + len(marker)] = marker
    for name, (site, target) in lk.CALLS.items():
        b[site:site + 4] = encode_thumb_bl(site, target)
    # For synthetic data these literals are in unused regions, not real code.
    literals = (0x1E8BC, 0x1F980, 0x1F9A8, 0x1F9B0)
    for (name, (ldr, add, target)), literal in zip(lk.LITERAL_REFERENCES.items(), literals):
        reg = 0 if name == "generic prefix" else 1
        ldr_pc_aligned = (ldr + 4) & ~3
        difference = literal - ldr_pc_aligned
        assert 0 <= difference <= 1020 and difference % 4 == 0
        struct.pack_into("<H", b, ldr, 0x4800 | reg << 8 | difference // 4)
        struct.pack_into("<H", b, add, 0x4400 | (15 << 3) | reg)
        struct.pack_into("<i", b, literal, target - add - 4)
    # CBZ r0 from 0x1F808 to 0x1F818.
    branch_site, branch_dest = 0x1F808, 0x1F818
    imm = branch_dest - branch_site - 4
    struct.pack_into("<H", b, branch_site,
                     0xB100 | (((imm >> 6) & 1) << 9) |
                     (((imm >> 1) & 31) << 3))
    return bytes(b)


class UnlockInspectorTests(unittest.TestCase):
    def setUp(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("Optional Capstone not installed")

    def test_decodes_synthetic_command_graph(self):
        sha, calls = lk.inspect(synthetic_lk(), strict=False)
        self.assertEqual(len(sha), 64)
        self.assertEqual(len(calls), len(lk.CALLS))
        self.assertEqual(calls["unlock validation"], (0x1F804, 0x1C48))

    def test_sha256_pinning_rejects_unknown_image(self):
        with self.assertRaisesRegex(ValueError, "not the expected"):
            lk.inspect(synthetic_lk(), strict=True)

    def test_rejects_wrong_unlock_handler_call(self):
        b = bytearray(synthetic_lk())
        b[0x1F804:0x1F808] = encode_thumb_bl(0x1F804, 0x1C4A)
        with self.assertRaisesRegex(ValueError, "Unexpected call"):
            lk.inspect(bytes(b), strict=False)

    def test_rejects_moved_string_reference(self):
        b = bytearray(synthetic_lk())
        struct.pack_into("<i", b, 0x1F980, 0x2DF97 - 0x1F7F8 - 4)
        with self.assertRaisesRegex(ValueError, "string reference mismatch"):
            lk.inspect(bytes(b), strict=False)

    def test_rejects_missing_vendor_signature_marker(self):
        b = bytearray(synthetic_lk())
        b[0x25230] = 0
        with self.assertRaisesRegex(ValueError, "Missing verified string"):
            lk.inspect(bytes(b), strict=False)

    def test_rejects_modified_unlock_success_gate(self):
        b = bytearray(synthetic_lk())
        struct.pack_into("<H", b, 0x1F808, 0xBF00)  # NOP
        with self.assertRaisesRegex(ValueError, "status branch"):
            lk.inspect(bytes(b), strict=False)


if __name__ == "__main__":
    unittest.main()

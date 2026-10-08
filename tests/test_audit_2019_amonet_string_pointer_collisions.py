"""Manufactured string regions; no proprietary preloader bytes."""
import hashlib
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_2019_amonet_string_pointer_collisions import (
    analyze_2019, macro_addr, printable_nul_string_covering)
from disassemble_preloader import address_to_offset

H = (
    "#define TEE_SET_ENTRY_ADDR 0x00215fe8\n"
    "#define MTEE_VERIFY_DECRYPT_ADDR 0x0021a7ec\n"
)


def fake_old_preloader():
    b = bytearray(0x30000)
    gfh = 0x6000
    b[gfh:gfh + 4] = b"MMM\x01"
    struct.pack_into("<I", b, gfh + 4, 0x38)
    b[gfh + 8:gfh + 18] = b"FILE_INFO\x00"
    struct.pack_into("<I", b, gfh + 0x1c, 0x200D00)
    b[gfh + 0x304:gfh + 0x308] = b"\x03\x00\x00\xea"

    for addr, value, before in (
        (0x215FE8, b"[CA Training] Frequency=%d, Rank=%d\n", 27),
        (0x21A7EC, b"the MTEE image required external memory size\n", 15),
    ):
        off = address_to_offset(b, addr)
        st = off - before
        b[st:st + len(value)] = value
        b[st + len(value)] = 0
    return bytes(b)


class PointerAsciiTests(unittest.TestCase):
    def test_parses_original_style_header(self):
        self.assertEqual(macro_addr(H, "TEE_SET_ENTRY_ADDR"), 0x215FE8)

    def test_reject_duplicate_macro(self):
        with self.assertRaisesRegex(ValueError, "Expected one"):
            macro_addr(H + H, "TEE_SET_ENTRY_ADDR")

    def test_printable_string_contains_target(self):
        d = b"\0Prefix text with enough alphabetic characters here\0"
        site = d.index(b"alphabetic")
        result = printable_nul_string_covering(d, site)
        self.assertIsNotNone(result)
        self.assertIn("alphabetic", result["ascii"])

    def test_reject_short_lone_printable_region(self):
        self.assertIsNone(printable_nul_string_covering(b"\0hey there\0", 4))

    def test_reject_binary_noise(self):
        self.assertIsNone(printable_nul_string_covering(
            b"\0Abcd \x01 random bytes in memory\0", 10))

    def test_unknown_image_sha_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned public"):
            analyze_2019(H, fake_old_preloader())

    def test_synthetic_pinned_2019_pointer_collisions(self):
        d = fake_old_preloader()
        digest = hashlib.sha256(d).hexdigest()
        with patch("audit_2019_amonet_string_pointer_collisions.PUBLIC_2019_IMAGE_SHA256",
                   digest):
            result = analyze_2019(H, d)
        self.assertEqual(set(result), {
            "TEE_SET_ENTRY_ADDR", "MTEE_VERIFY_DECRYPT_ADDR"})
        self.assertIn("[CA Training]", result["TEE_SET_ENTRY_ADDR"]["ascii"])
        self.assertIn("MTEE image required",
                      result["MTEE_VERIFY_DECRYPT_ADDR"]["ascii"])

    def test_modified_header_pointer_fails(self):
        d = fake_old_preloader()
        digest = hashlib.sha256(d).hexdigest()
        bad = H.replace("0x00215fe8", "0x00215f00")
        with patch("audit_2019_amonet_string_pointer_collisions.PUBLIC_2019_IMAGE_SHA256",
                   digest), self.assertRaises(ValueError):
            analyze_2019(bad, d)


if __name__ == "__main__":
    unittest.main()

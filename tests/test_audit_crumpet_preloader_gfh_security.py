"""Manufactured GFH type+length chain, no original MediaTek image bytes."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_crumpet_preloader_gfh_security import (
    EXPECTED_CHAIN, parse_chain, compare_chains,
)

SIZES = (0x38, 0xC, 0x64, 0x14, 0x30, 0x214)


def artificial_header(length=150000, modify_type=None, modify_payload=None,
                      sig_size=292):
    data = bytearray(184320)
    off = 0x8000
    for i, (typ, size) in enumerate(zip(EXPECTED_CHAIN, SIZES)):
        if i == 0:
            struct.pack_into("<IHH12sIHBBIIIIIII", data, off,
                             0x014D4D4D, size, 0,
                             b"FILE_INFO\x00\x00\x00", 1, 1, 5, 3,
                             0x200D00, length, 262144, 768,
                             sig_size, 768, 0xC2600001)
        else:
            struct.pack_into("<IHH", data, off,
                             0x014D4D4D, size,
                             modify_type if modify_type is not None and i == 2
                             else typ)
            data[off + 8:off + size] = bytes([i]) * (size - 8)
        if modify_payload is not None and i == modify_payload:
            data[off + size - 1] ^= 0x5A
        off += size
    assert off == 0x8300
    data[0x8304:0x8308] = bytes.fromhex("030000ea")
    return bytes(data)


class GfhChainTests(unittest.TestCase):
    def test_synthetic_gfh_fields_and_types(self):
        r = parse_chain(artificial_header(), require_known=False)
        self.assertEqual(r["signature_type"], 3)
        self.assertEqual(r["signature_size"], 292)
        self.assertEqual([x["type"] for x in r["records"]],
                         list(EXPECTED_CHAIN))
        self.assertEqual(r["gfh_image_length"], 150000)

    def test_only_file_info_diff_when_size_changes(self):
        a = parse_chain(artificial_header(), require_known=False)
        b = parse_chain(artificial_header(length=150148), require_known=False)
        comparison = compare_chains([a, b])
        self.assertFalse(comparison[0]["byte_identical_across_all"])
        self.assertTrue(all(x["byte_identical_across_all"]
                            for x in comparison[1:]))

    def test_changing_security_field_is_detectable(self):
        a = parse_chain(artificial_header(), require_known=False)
        b = parse_chain(artificial_header(modify_payload=5),
                        require_known=False)
        result = compare_chains([a, b])
        self.assertFalse(result[-1]["byte_identical_across_all"])

    def test_unknown_firmware_fails_closed_by_default(self):
        with self.assertRaisesRegex(ValueError, "Unpinned"):
            parse_chain(artificial_header())

    def test_invalid_signature_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "signature/image"):
            parse_chain(artificial_header(sig_size=262144),
                        require_known=False)

    def test_changed_gfh_type_sequence_rejected(self):
        with self.assertRaisesRegex(ValueError, "type sequence"):
            parse_chain(artificial_header(modify_type=11),
                        require_known=False)

    def test_missing_gfh_header_rejected(self):
        data = bytearray(artificial_header())
        data[0x8000] = 0
        with self.assertRaisesRegex(ValueError, "validated"):
            parse_chain(bytes(data), require_known=False)

    def test_require_two_images_for_comparison(self):
        r = parse_chain(artificial_header(), require_known=False)
        with self.assertRaisesRegex(ValueError, "Two"):
            compare_chains([r])


if __name__ == "__main__":
    unittest.main()

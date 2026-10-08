"""Synthetic file/patch sources only; no proprietary firmware included."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_amonet_patch_sites import (
    audit_image, confirm_unadjusted_patch_writer,
    nearby_ascii_sequences, parse_patch_sites,
)

C = """
void apply_patches(void) {
    patch_ret(0x00217F2C, 0);
    patch_word(0x00217548, 0xBF00447D);
    patch_ret(0x002019B0, 0);
    patch_ret(0x00201954, 0);
    patch_branch(0x0020E19C, replacement_tee);
}
"""

PATCH_C = """
void patch_word(uint32_t addr, uint32_t value)
{
    writel(value, addr);
    invalidate_icache_range(addr, sizeof(value));
}
void patch_ret(uint32_t addr, uint32_t value) {
    patch_word(addr, 0x47702000);
}
void patch_thumb_branch(uint32_t addr) {
    writew(0xf000, addr);
    writew(0x9000, addr + 2);
}
"""

LOAD = 0x00200D00


def synthetic_image(base=0x8000, length=0x2D000):
    data = bytearray(length)
    data[base:base + 4] = b"MMM\x01"
    struct.pack_into("<I", data, base + 4, 0x38)
    data[base + 8:base + 18] = b"FILE_INFO\x00"
    struct.pack_into("<I", data, base + 0x1c, LOAD)
    data[base + 0x304:base + 0x308] = b"\x03\x00\x00\xea"
    return data


class PatchMappingTests(unittest.TestCase):
    def test_extract_all_five_declared_addresses(self):
        sites = parse_patch_sites(C)
        self.assertEqual(len(sites), 5)
        self.assertEqual(sites[0]["address"], 0x217F2C)
        self.assertEqual(sites[4]["operation"], "patch_branch")

    def test_exact_writer_semantics_required(self):
        self.assertTrue(confirm_unadjusted_patch_writer(PATCH_C))
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            confirm_unadjusted_patch_writer(
                PATCH_C.replace("writel(value, addr)", "writel(value, translate(addr))"))

    def test_2019_and_newer_file_offset_shift(self):
        sites = parse_patch_sites(C)
        old = synthetic_image(base=0x6000)
        recent = synthetic_image(base=0x8000)
        older_result = audit_image(bytes(old), sites, decode_thumb=False)
        newer_result = audit_image(bytes(recent), sites, decode_thumb=False)
        self.assertEqual(older_result["sites"][0]["offset"], 0x1D52C)
        self.assertEqual(newer_result["sites"][0]["offset"], 0x1F52C)
        self.assertEqual(older_result["encoded_load"], LOAD)

    def test_ascii_marker_inside_site_detected(self):
        binary = synthetic_image()
        target = 0x1F52C
        literal = b"error, value: %x\\n"
        binary[target - 4:target - 4 + len(literal)] = literal
        hit = audit_image(bytes(binary), parse_patch_sites(C), decode_thumb=False)
        self.assertTrue(hit["sites"][0]["nearby_printable"])
        self.assertTrue(hit["sites"][0]["nearby_printable"][0]["contains_site"])

    def test_disallowed_duplicate_address(self):
        source = C + "\npatch_ret(0x00217F2C, 0);"
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_patch_sites(source)

    def test_marker_search_does_not_mislabel_far_strings(self):
        blob = b"example error string\x00" + bytes(60)
        self.assertEqual(nearby_ascii_sequences(blob, len(blob) - 1), [])

    def test_truncated_firmware_range_rejected(self):
        with self.assertRaises(ValueError):
            audit_image(bytes(synthetic_image(length=0x8500)),
                        parse_patch_sites(C), decode_thumb=False)


if __name__ == "__main__":
    unittest.main()

"""Manufactured GFH + embedded EMI fixtures; no Amazon/MediaTek binary copied."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_crumpet_emi_fallback import (
    EMI_LEN, EMI_MARKER, GFH_MARKER, direct_embedded_emi,
    gfhsigned_slice, inspect_brom_autoselect_source, inspect_image,
    reproduce_upstream_m_extract_emi,
)


def fabricated_preloader(legacy_padded=False):
    # Manufacture a plausible but completely fake versioned field and
    # "MTK_BIN" marker, NOT the actual copyrighted EMI body.
    start = 0x100
    image = bytearray(b"\xA5" * 0x6000)
    image[start:start + 8] = GFH_MARKER
    emi_start = 0x1500
    emi = bytearray(b"\0" * EMI_LEN)
    emi[:len(EMI_MARKER)] = EMI_MARKER
    emi[len(EMI_MARKER):len(EMI_MARKER) + 1] = b"\x00"
    emi[0x64:0x6B] = b"MTK_BIN"
    emi[0x70:0x78] = b"madeup!!"
    image[emi_start:emi_start + EMI_LEN] = emi
    struct.pack_into("<I", image, emi_start + EMI_LEN, EMI_LEN)

    signature_length = 292
    if legacy_padded:
        # Full GFH-declared clipping reaches ff-padding instead of the
        # actual valid 400-byte EMI trailer, recreating the 2019 false match.
        signed_end = 0x3000
        image[signed_end - 0x400:signed_end] = b"\xff" * 0x400
    else:
        signed_end = emi_start + EMI_LEN + 4
    mlen = signed_end - start + signature_length
    struct.pack_into("<I", image, start + 0x20, mlen)
    struct.pack_into("<I", image, start + 0x2c, signature_length)
    return bytes(image)


SYNTHETIC_XFLASH = """
class DAXFlash:
    def upload_da(self):
        if connagent == b"brom":
            emmc_info = self.get_emmc_info(False)
            ufs_info = self.get_ufs_info()
            if emmc_info.cid[:8] in data:
                self.daconfig.extract_emi(preloader)
            self.send_emi(self.daconfig.emi)
        elif connagent == b"preloader":
            pass
"""


class CrumpetEmiAuditTests(unittest.TestCase):
    def test_current_style_400_byte_extract_matches_embedded(self):
        img = fabricated_preloader()
        result = inspect_image(img, require_known=False)
        self.assertEqual(result["embedded_emi_length"], 400)
        self.assertEqual(result["mtkclient_emilen"], 400)
        self.assertTrue(result["legacy_result_matches_verified_embedded_emi"])
        self.assertEqual(result["gfh_signed_slice_tail_word"], 400)

    def test_legacy_2019_style_padding_selects_wrong_suffix(self):
        img = fabricated_preloader(legacy_padded=True)
        result = inspect_image(img, require_known=False)
        self.assertEqual(result["embedded_emi_length"], 400)
        self.assertEqual(result["gfh_signed_slice_tail_word"], 0xFFFFFFFF)
        self.assertEqual(result["mtkclient_emiver"], 28)
        self.assertGreater(result["mtkclient_emilen"], 400)
        self.assertFalse(result["legacy_result_matches_verified_embedded_emi"])

    def test_reject_unknown_image_by_default(self):
        with self.assertRaisesRegex(ValueError, "Unknown preloader"):
            direct_embedded_emi(fabricated_preloader())

    def test_broken_embedded_length_footer_rejected(self):
        img = bytearray(fabricated_preloader())
        off = img.find(EMI_MARKER)
        struct.pack_into("<I", img, off + EMI_LEN, 1024)
        with self.assertRaisesRegex(ValueError, "footer"):
            direct_embedded_emi(bytes(img), require_known=False)

    def test_two_embedded_markers_rejected(self):
        img = bytearray(fabricated_preloader())
        img[0x2400:0x2400 + len(EMI_MARKER)] = EMI_MARKER
        with self.assertRaisesRegex(ValueError, "exactly one embedded"):
            direct_embedded_emi(bytes(img), require_known=False)

    def test_corrupt_gfh_bounds_rejected(self):
        img = bytearray(fabricated_preloader())
        struct.pack_into("<I", img, 0x100 + 0x2c, 500000)
        with self.assertRaisesRegex(ValueError, "declared lengths"):
            gfhsigned_slice(bytes(img))

    def test_synthetic_2019_actual_reproduction_larger(self):
        img = fabricated_preloader(legacy_padded=True)
        result = reproduce_upstream_m_extract_emi(img)
        self.assertIsNotNone(result)
        ver, data = result
        self.assertEqual(ver, 28)
        self.assertNotEqual(data[:len(EMI_MARKER)], EMI_MARKER)
        self.assertGreater(len(data), EMI_LEN)

    def test_nand_not_consulted_in_existing_brom_auto_discovery(self):
        result = inspect_brom_autoselect_source(SYNTHETIC_XFLASH)
        self.assertTrue(result["brom_attempts_emmc_info_autodiscovery"])
        self.assertTrue(result["brom_attempts_ufs_info_autodiscovery"])
        self.assertFalse(result["brom_attempts_raw_nand_id_autodiscovery"])
        self.assertTrue(result["brom_matches_candidate_files_by_cid"])

    def test_detect_future_nand_id_autodiscovery(self):
        future = SYNTHETIC_XFLASH.replace(
            "            ufs_info = self.get_ufs_info()",
            "            ufs_info = self.get_ufs_info()\n"
            "            nand_info = self.get_nand_info(False)")
        result = inspect_brom_autoselect_source(future)
        self.assertTrue(result["brom_attempts_raw_nand_id_autodiscovery"])

    def test_changed_brom_selector_fails_closed(self):
        source = SYNTHETIC_XFLASH.replace('b"brom"', 'b"preloader"')
        with self.assertRaisesRegex(ValueError, "one original BROM"):
            inspect_brom_autoselect_source(source)


if __name__ == "__main__":
    unittest.main()

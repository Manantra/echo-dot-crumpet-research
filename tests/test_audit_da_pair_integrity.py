"""Synthetic DA containers for offline SHA-bound Stage-1/Stage-2 pairing checks."""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da_pair_integrity import audit, digest_references, read_pair
from audit_mtkclient_da_metadata import scan_directory
from test_audit_mtkclient_da_metadata import artificial_loader


def synth_pair(path, variant, signature_tail=0x10):
    artificial_loader(path)
    content = bytearray(path.read_bytes())
    first = 0x6c + 20
    struct.pack_into("<IIIII", content, first + 1 * 20,
                     0x300, 0x80, 0x00200000, 0, 0)
    struct.pack_into("<IIIII", content, first + 2 * 20,
                     0x400, 0x80, 0x40000000, 0, signature_tail)
    content[0x410] = variant
    content[0x47F] = 0xFF
    effective = bytes(content[0x400:0x480 - signature_tail])
    digest = hashlib.sha1(effective).digest()
    content[0x320:0x320 + 20] = digest
    path.write_bytes(content)


class PairDigestTests(unittest.TestCase):
    def test_pair_digests_match_only_their_own_stage2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synth_pair(root / "MTK_DA_V5.bin", 1)
            synth_pair(root / "MTK_AllInOne_DA_alt.bin", 2)
            matrix = audit(root)
            self.assertEqual(len(matrix), 2)
            for row in matrix:
                for result in row["candidates"]:
                    self.assertEqual(bool(result["digest_refs"]),
                                     result["same_container"])
                    if result["same_container"]:
                        self.assertIn("SHA1", result["digest_refs"])

    def test_tail_not_included_in_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "MTK_DA_V5.bin"
            synth_pair(p, 11)
            rows, _, _ = scan_directory(Path(tmp))
            da1, da2 = read_pair(Path(tmp), rows[0])
            self.assertIn("SHA1", digest_references(da1, da2))
            self.assertNotIn("SHA1", digest_references(
                da1, p.read_bytes()[0x400:0x480]))

    def test_damaged_da2_invalidates_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "MTK_DA_V5.bin"
            synth_pair(p, 3)
            data = bytearray(p.read_bytes())
            data[0x425] ^= 0x10
            p.write_bytes(data)
            rows = audit(Path(tmp))
            self.assertFalse(rows[0]["candidates"][0]["digest_refs"])

    def test_short_container_region_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "MTK_DA_V5.bin"
            synth_pair(p, 3)
            data = bytearray(p.read_bytes())
            # Corrupt signature tail metadata to exceed data region.
            struct.pack_into("<I", data, 0x6c + 20 + 2*20 + 16, 0x100)
            p.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "Invalid DA2"):
                audit(Path(tmp))


if __name__ == "__main__":
    unittest.main()

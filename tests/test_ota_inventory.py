"""Synthetic, firmware-free tests for ota_inventory.py."""
import contextlib
import hashlib
import io
import lzma
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ota_inventory as ota


def vi(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return vi((number << 3) | 0) + vi(value)
    return vi((number << 3) | 2) + vi(len(value)) + value


def fixture(path, damage=False, name="brhgptpl_0"):
    raw = (b"BOOTLOADER! test 20210326_040236 test "
           b"check_part_overlapped done").ljust(4096, b"\x00")
    compressed = lzma.compress(raw)
    extent = field(1, 0) + field(2, 1)
    op = (field(1, 8) + field(2, 0) + field(3, len(compressed)) +
          field(6, extent) + field(8, hashlib.sha256(compressed).digest()))
    partition_info = field(1, len(raw)) + field(2, hashlib.sha256(raw).digest())
    partition = field(1, name.encode("ascii")) + field(7, partition_info) + field(8, op)
    manifest = field(3, 4096) + field(13, partition)
    payload = (b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) +
               manifest + compressed)
    if damage:
        payload = payload[:-1] + bytes([payload[-1] ^ 1])
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("payload.bin", payload, compress_type=zipfile.ZIP_STORED)


class ManifestTests(unittest.TestCase):
    def test_synthetic_preloader_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fake-ota.zip"
            fixture(path)
            with zipfile.ZipFile(path) as z:
                parts, start, block, version = ota.parse_manifest(z)
                self.assertEqual((block, version), (4096, 2))
                self.assertEqual(parts[0]["name"], "brhgptpl_0")
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    ota.verify_brhgptpl(z, parts, start, block)
                self.assertIn("VERIFIED brhgptpl_0", out.getvalue())

    def test_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corrupt.zip"
            fixture(path, damage=True)
            with zipfile.ZipFile(path) as z:
                parts, start, block, _ = ota.parse_manifest(z)
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    ota.verify_brhgptpl(z, parts, start, block)

    def test_truncated_protobuf_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            list(ota.fields(b"\x0a\x10a"))


if __name__ == "__main__":
    unittest.main()

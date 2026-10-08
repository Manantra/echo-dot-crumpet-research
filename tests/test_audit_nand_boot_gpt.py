"""Firmware-free manufactured NAND/GPT fixtures for exact header/CRC analysis."""
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_nand_boot_gpt import inspect_image, classify_differences

PARTS = (("brhgptpl_0", 0), ("brhgptpl_1", 0x400),
         ("brhgptpl_2", 0x800), ("brhgptpl_3", 0xC00),
         ("lk_a", 0x100))


def update_crc(data):
    """Recalculate internal CRCs on synthetic GPT metadata only."""
    table = data[0x4000:0x5000]
    struct.pack_into("<I", data, 0x3000 + 0x58, zlib.crc32(table))
    struct.pack_into("<I", data, 0x3000 + 0x10, 0)
    crc = zlib.crc32(data[0x3000:0x3000 + 92])
    struct.pack_into("<I", data, 0x3000 + 0x10, crc)


def synthetic_nand(copy=0, version_marker=4):
    b = bytearray(0x9000)
    head = bytearray(128)
    head[:12] = b"BOOTLOADER!\x00"
    head[12:16] = b"V006"
    head[16:24] = b"NFIINFO\x00"
    struct.pack_into("<HHH", head, 24, 0x100, 4096, 5)
    b[:128] = head
    b[0x100:0x180] = head
    b[0x1000:0x1008] = b"BRLYT\x00\x00\x00"
    partition_lba = copy * 0x400
    struct.pack_into("<8I", b, 0x1008, 1, partition_lba + 8,
                     partition_lba + 0x108, 0x42424242, 0x10002,
                     partition_lba + 8, partition_lba + 0x108, 1)
    b[0x3000:0x3008] = b"EFI PART"
    struct.pack_into("<II", b, 0x3008, 0x10000, 92)
    struct.pack_into("<QQQQ", b, 0x3018, 1, 1, 3, 0x1fffd)
    b[0x3038:0x3048] = bytes([version_marker]) * 16
    struct.pack_into("<QII", b, 0x3048, 2, 32, 128)
    for i, (name, first) in enumerate(PARTS):
        off = 0x4000 + i * 128
        b[off:off + 16] = b"\x10" * 16
        b[off + 16:off + 32] = bytes([version_marker + i]) * 16
        struct.pack_into("<QQQ", b, off + 32, first, first + 0x3f, 0)
        b[off + 56:off + 56 + 2 * len(name)] = name.encode("utf-16le")
    b[0x8000:0x8004] = b"MMM\x01"
    update_crc(b)
    return bytes(b)


class NandGptTests(unittest.TestCase):
    def test_recognizes_synthetic_gpt_and_crc(self):
        r = inspect_image(synthetic_nand())
        self.assertEqual(r["nand_pagesize"], 4096)
        self.assertEqual(r["gpt_nentries"], 32)
        self.assertEqual(r["gpt_entries_used"], 5)
        self.assertEqual(r["brlyt_matches_gpt_copy"], "brhgptpl_0")

    def test_all_four_copy_positions_link_to_gpt(self):
        for i in range(4):
            with self.subTest(copy=i):
                r = inspect_image(synthetic_nand(copy=i))
                self.assertEqual(r["brlyt_matches_gpt_copy"], f"brhgptpl_{i}")

    def test_2019_archive_container_offset_layout(self):
        # Manufactured copy of the same metadata at the archived 2019 file
        # offsets: BRLYT 0xC00, GPT 0x2400, table 0x3000, GFH 0x6000.
        modern = synthetic_nand()
        old = bytearray(0x9000)
        old[:0x200] = modern[:0x200]
        old[0xC00:0xC28] = modern[0x1000:0x1028]
        old[0x2400:0x245C] = modern[0x3000:0x305C]
        old[0x3000:0x4000] = modern[0x4000:0x5000]
        old[0x6000:0x6004] = b"MMM\\x01"
        result = inspect_image(bytes(old))
        self.assertEqual(result["gfh_offset"], 0x6000)
        self.assertEqual(result["gpt_offset"], 0x2400)
        self.assertEqual(result["entries_offset"], 0x3000)
        self.assertEqual(result["brlyt_matches_gpt_copy"], "brhgptpl_0")
        self.assertEqual(result["partitions"], inspect_image(modern)["partitions"])

    def test_2019_and_modern_wrappers_not_direct_byte_comparable(self):
        modern = synthetic_nand()
        old = bytearray(0x9000)
        old[:0x200] = modern[:0x200]
        old[0xC00:0xC28] = modern[0x1000:0x1028]
        old[0x2400:0x245C] = modern[0x3000:0x305C]
        old[0x3000:0x4000] = modern[0x4000:0x5000]
        old[0x6000:0x6004] = b"MMM\\x01"
        with self.assertRaisesRegex(ValueError, "container layouts differ"):
            classify_differences(bytes(old), modern)

    def test_header_crc_rejects_tampering(self):
        b = bytearray(synthetic_nand())
        b[0x3008] ^= 1
        with self.assertRaisesRegex(ValueError, "header CRC32"):
            inspect_image(bytes(b))

    def test_partition_crc_rejects_tampering(self):
        b = bytearray(synthetic_nand())
        b[0x4020] ^= 1
        with self.assertRaisesRegex(ValueError, "entry table CRC32"):
            inspect_image(bytes(b))

    def test_all_guid_and_crc_changes_are_classified(self):
        a = synthetic_nand(version_marker=4)
        b = synthetic_nand(version_marker=5)
        categories = classify_differences(a, b)
        self.assertEqual(categories["other"], 0)
        self.assertEqual(categories["gpt_disk_guid"], 16)
        self.assertEqual(categories["gpt_unique_partition_guids"], 5 * 16)
        self.assertGreater(categories["gpt_header_crc"], 0)
        self.assertGreater(categories["gpt_partition_array_crc"], 0)

    def test_partition_geometry_change_is_not_classed_as_guid(self):
        a = synthetic_nand()
        b = bytearray(a)
        struct.pack_into("<Q", b, 0x4000 + 32, 1)
        update_crc(b)
        categories = classify_differences(a, bytes(b))
        self.assertGreater(categories["other"], 0)

    def test_wrong_gfh_rejected(self):
        b = bytearray(synthetic_nand())
        b[0x8000] ^= 0x11
        with self.assertRaisesRegex(ValueError, "GFH"):
            inspect_image(bytes(b))

    def test_wrong_redundant_nand_header_rejected(self):
        b = bytearray(synthetic_nand())
        b[0x10A] ^= 0x11
        with self.assertRaisesRegex(ValueError, "NAND V006 header"):
            inspect_image(bytes(b))

    def test_unsupported_gpt_extent_rejected(self):
        b = bytearray(synthetic_nand())
        struct.pack_into("<I", b, 0x3000 + 0x50, 999)
        update_crc(b)
        with self.assertRaisesRegex(ValueError, "table bounds"):
            inspect_image(bytes(b))


if __name__ == "__main__":
    unittest.main()

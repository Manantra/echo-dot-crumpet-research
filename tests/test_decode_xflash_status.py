"""Synthetic XFLASH status protocol tests. No USB traffic or devices used."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from decode_xflash_status import BOOTTOSUCCESS, MAGIC, decode_frame


def frame(status, length=4):
    return struct.pack("<III", MAGIC, 1, length) + status.to_bytes(length, "little")


class XFlashStatusTests(unittest.TestCase):
    def test_short_header_is_not_dram_diagnosis(self):
        state = decode_frame(b"\xef\xee\xee\xfe")
        self.assertEqual(state["state"], "short_header")
        self.assertIn("cause unknown", state["message"])

    def test_frame_with_success_zero(self):
        state = decode_frame(frame(0))
        self.assertTrue(state["boot_to_success"])
        self.assertEqual(state["status"], 0)

    def test_frame_with_sync_success(self):
        state = decode_frame(frame(BOOTTOSUCCESS))
        self.assertTrue(state["boot_to_success"])
        self.assertEqual(state["status"], BOOTTOSUCCESS)

    def test_mt_protocol_magic_status_normalizes_to_zero(self):
        state = decode_frame(frame(MAGIC))
        self.assertEqual(state["status"], 0)

    def test_non_success_error_still_has_frame(self):
        state = decode_frame(frame(0xC0020053))
        self.assertEqual(state["state"], "complete")
        self.assertFalse(state["boot_to_success"])
        self.assertEqual(state["status"], 0xC0020053)

    def test_short_payload(self):
        data = frame(0xC0020053)[:14]
        self.assertEqual(decode_frame(data)["state"], "short_payload")

    def test_corrupted_magic(self):
        data = bytearray(frame(0))
        data[0] = 0
        self.assertEqual(decode_frame(bytes(data))["state"], "wrong_magic")

    def test_no_payload_not_success(self):
        data = struct.pack("<III", MAGIC, 1, 0)
        self.assertEqual(decode_frame(data)["state"], "empty_payload")

    def test_unreasonable_length(self):
        data = struct.pack("<III", MAGIC, 1, 0xFFFFFFFF)
        self.assertEqual(decode_frame(data)["state"], "invalid_length")

    def test_short_two_byte_status(self):
        data = frame(0x2001, length=2)
        result = decode_frame(data)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(result["boot_to_success"])


if __name__ == "__main__":
    unittest.main()

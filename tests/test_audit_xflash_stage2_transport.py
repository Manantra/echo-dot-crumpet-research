"""Manufactured USB frames and source AST; never contact a device."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_xflash_stage2_transport import (
    MAGIC, classify_status_reply, method_audit, method_from_file,
)

XFLASH = """
class DAXFlash:
    def status(self):
        hdr = self.usbread(12)
        magic, _, length = unpack("<III", hdr)
        tmp = self.usbread(length)
        return unpack("<I", tmp)[0]

    def boot_to(self, addr, da, display=True, timeout=0.5):
        if self.send_data(da):
            if timeout:
                time.sleep(timeout)
            try:
                status = self.status()
            except Exception:
                self.error("Stage was't executed. Maybe dram issue ?.")
                return False

    def send_data(self, data):
        bytestowrite = len(data)
        while bytestowrite > 0:
            if self.usbwrite(data):
                bytestowrite -= 1

    def upload_da(self):
        done = self.boot_to(0x40000000, b"")
        if done:
            self.reinit(True)

    def reinit(self, display=False):
        self.mtk.port.close(reset=True)
        while not self.mtk.port.cdc.connect():
            pass
"""

USB = """
class UsbClass:
    def usbread(self, resplen=None, maxtimeout=100):
        if self.no_reply:
            return b""
        return b"ok"
"""


class Stage2OfflineTests(unittest.TestCase):
    def test_pinned_source_shape_captured(self):
        r = method_audit(XFLASH, USB)
        self.assertTrue(r["boot_exception_mapped_to_generic_dram_line"])
        self.assertTrue(r["boot_timeout_controls_sleep_not_usb_read"])
        self.assertTrue(r["send_data_can_spin_after_usbwrite_false"])
        self.assertTrue(r["usbread_can_return_empty"])
        self.assertEqual(r["usbread_default_max_timeout_retries"], 100)
        self.assertTrue(r["stage2_reconnect_deferred_until_after_boot_success"])

    def test_send_loop_with_safe_else_detected(self):
        safer = XFLASH.replace(
            "                bytestowrite -= 1",
            "                bytestowrite -= 1\n            else:\n                break")
        r = method_audit(safer, USB)
        self.assertFalse(r["send_data_can_spin_after_usbwrite_false"])

    def test_dedicated_boot_read_timeout_detected(self):
        changed = XFLASH.replace(
            "status = self.status()", "status = self.status(maxtimeout=10)")
        r = method_audit(changed, USB)
        self.assertFalse(r["boot_timeout_controls_sleep_not_usb_read"])

    def test_missing_status_function_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "method"):
            method_from_file(XFLASH, "DAXFlash", "imaginary")

    def test_empty_header_is_exception_giving_generic_dram_line(self):
        r = classify_status_reply(b"")
        self.assertIn("EXCEPTION_SHORT_HEADER", r)
        self.assertIn("GENERIC_DRAM", r)

    def test_short_payload_returns_minus_one_without_generic_line(self):
        header = struct.pack("<III", MAGIC, 1, 4)
        r = classify_status_reply(header, b"\x00")
        self.assertIn("NEGATIVE_ONE_SHORT_PAYLOAD", r)
        self.assertIn("NO_GENERIC_DRAM", r)

    def test_zero_and_sync_success(self):
        h = struct.pack("<III", MAGIC, 1, 4)
        for code in (0, 0x434E5953, MAGIC):
            with self.subTest(code=code):
                self.assertEqual(classify_status_reply(h, struct.pack("<I", code)),
                                 "STATUS_SUCCESS")

    def test_explicit_protocol_error_is_not_generic_exception(self):
        h = struct.pack("<III", MAGIC, 1, 4)
        r = classify_status_reply(h, struct.pack("<I", 0xC0050005))
        self.assertEqual(r,
                         "STATUS_EXPLICIT_ERROR_0xC0050005__NO_GENERIC_DRAM_LINE")

    def test_wrong_magic_is_not_generic_exception(self):
        h = struct.pack("<III", 123, 1, 4)
        self.assertTrue(
            classify_status_reply(h, b"\x00" * 4)
            .startswith("NEGATIVE_ONE_WRONG_MAGIC"))

    def test_malformed_status_length_categorized_as_exception(self):
        h = struct.pack("<III", MAGIC, 1, 1)
        self.assertIn("EXCEPTION_MALFORMED_LENGTH",
                      classify_status_reply(h, b"\x00"))


if __name__ == "__main__":
    unittest.main()

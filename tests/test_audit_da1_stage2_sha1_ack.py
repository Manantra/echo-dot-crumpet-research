"""No device, DA binary bytes or MTKClient invocation; entirely synthetic."""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da1_stage2_sha1_ack import (
    TARGETS, compare_sha1, host_gate, validate_binary_pair,
)

HOST_SOURCE = '''
class DAXFlash:
    def send_data(self, data):
        if self.usbwrite(data):
            status = self.status()
            if status == 0:
                return True
            self.error("DA1 data rejected")
        return False

    def boot_to(self, addr, da, display=True):
        if self.xsend(self.cmd.BOOT_TO):
            if self.send_data(da):
                self.info("Upload data was accepted. Jumping to stage 2...")
                status = self.status()
                if status == 0x434E5953:
                    return True
        return False
'''


class Stage2AcknowledgmentTests(unittest.TestCase):
    def test_stock_originals_are_distinct_and_have_same_failure_code(self):
        self.assertEqual(set(TARGETS), {
            "MTK_DA_V5.bin", "MTK_AllInOne_DA_mt6590.bin"})
        self.assertEqual({p["failure_code"] for p in TARGETS.values()},
                         {0xC0070004})
        self.assertNotEqual(*[p["expected_sha1_addr"] for p in TARGETS.values()])

    def test_sha1_digest_matches_original_synthetic_image(self):
        image = b"synthetic DA2 only"
        expected = hashlib.sha1(image).digest()
        self.assertTrue(compare_sha1(expected, image))

    def test_changed_da2_is_rejected(self):
        image = b"synthetic DA2 only"
        expected = hashlib.sha1(image).digest()
        self.assertFalse(compare_sha1(expected, image + b"\0"))

    def test_wrong_sha_length_rejected(self):
        with self.assertRaisesRegex(ValueError, "20 bytes"):
            compare_sha1(b"\0" * 19, b"manufactured")

    def test_host_gate_separates_prestage_transfer_from_boot_success(self):
        r = host_gate(HOST_SOURCE)
        self.assertTrue(r["log_only_after_da_data_status_zero"])
        self.assertTrue(r["further_da2_status_read_after_accepted"])

    def test_no_status_zero_gate_fails_closed(self):
        altered = HOST_SOURCE.replace("if status == 0:", "if status >= 0:")
        with self.assertRaisesRegex(ValueError, "status==0"):
            host_gate(altered)

    def test_missing_acceptance_branch_fails_closed(self):
        altered = HOST_SOURCE.replace("if self.send_data(da):",
                                      "if self.usbwrite(da):")
        with self.assertRaisesRegex(ValueError, "send_data true branch"):
            host_gate(altered)

    def test_missing_second_stage_status_is_detected(self):
        altered = HOST_SOURCE.replace(
            '                status = self.status()\n'
            '                if status == 0x434E5953:',
            '                status = 0\n'
            '                if status == 0x434E5953:')
        with self.assertRaisesRegex(ValueError, "later Stage-2 status"):
            host_gate(altered)

    def test_acceptance_message_outside_gate_rejected(self):
        changed = HOST_SOURCE.replace(
            '                self.info("Upload data was accepted. Jumping to stage 2...")',
            '                self.info("transfer completed")')
        with self.assertRaisesRegex(ValueError, "Accepted log not under"):
            host_gate(changed)

    def test_unknown_container_sha_rejected_without_import_or_usb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            name = "MTK_DA_V5.bin"
            (root/name).write_bytes(b"not a genuine original DA container")
            with self.assertRaisesRegex(ValueError, "container SHA-256"):
                validate_binary_pair({"filename": name}, root)


if __name__ == "__main__":
    unittest.main()

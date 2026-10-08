"""Manufactured source snippets for AST-only XFLASH mode-flow verification."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_xflash_mode_flow import inspect_source

MOCK_SOURCE = '''
class DAXFlash:
    def upload_da1(self):
        self.mtk.preloader.send_da(1, 2, 3, b"fake")
        self.sync()
        self.setup_env()
        self.setup_hw_init()
        return self.xread() is not None

    def upload_da(self):
        if self.upload_da1():
            connagent = self.get_connection_agent()
            if connagent == b"brom":
                self.send_emi(b"fake")
            elif connagent == b"preloader":
                stage = 1
            return self.boot_to(123, b"fake")
'''


class FlowTests(unittest.TestCase):
    def test_flags_unchecked_calls_and_emi(self):
        report = inspect_source(MOCK_SOURCE)
        self.assertTrue(all(report["unchecked_setup_results"].values()))
        self.assertTrue(report["brom_explicit_emi"])
        self.assertFalse(report["preloader_explicit_emi"])
        self.assertTrue(report["both_call_stage2"])

    def test_checked_setup_env_changes_finding(self):
        changed = MOCK_SOURCE.replace("        self.setup_env()",
                                      "        if not self.setup_env():\n            return False")
        with self.assertRaisesRegex(ValueError, "unchecked setup calls"):
            inspect_source(changed)

    def test_missing_stage2_call_is_detected(self):
        changed = MOCK_SOURCE.replace("return self.boot_to(123, b\"fake\")",
                                      "return True")
        with self.assertRaisesRegex(ValueError, "two-stage upload flow"):
            inspect_source(changed)

    def test_emi_in_preloader_path_is_detected(self):
        changed = MOCK_SOURCE.replace("                stage = 1",
                                      "                stage = 1\n                self.send_emi(b'fake')")
        with self.assertRaisesRegex(ValueError, "EMI handling differs"):
            inspect_source(changed)

    def test_missing_brom_branch_is_detected(self):
        changed = MOCK_SOURCE.replace('connagent == b"brom"', 'connagent == b"usb"')
        with self.assertRaisesRegex(ValueError, "connection branches missing"):
            inspect_source(changed)


if __name__ == "__main__":
    unittest.main()

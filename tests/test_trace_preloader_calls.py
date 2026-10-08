"""Tests for generic Thumb BL call-site scanning without firmware assets."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import trace_preloader_calls as trace
from test_disassemble_preloader import sample_image


class CallScannerTests(unittest.TestCase):
    def test_decodes_synthetic_relative_bl(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("Optional Capstone is unavailable")
        image = bytearray(sample_image())
        # Generic Thumb BL +0 to the instruction immediately after the call:
        image[0x524:0x528] = b"\x00\xf0\x00\xf8"
        result = trace.direct_calls(bytes(image), 0x200d24, 4)
        self.assertEqual(result, [(0x200d24, 0x200d28, "bl")])

    def test_only_explicit_direct_calls(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("Optional Capstone is unavailable")
        image = bytearray(sample_image())
        image[0x524:0x526] = b"\x70\x47"  # bx lr
        result = trace.direct_calls(bytes(image), 0x200d24, 2)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()

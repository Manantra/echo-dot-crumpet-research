"""Manufactured C and NAND GPT fixtures for a read-only Crumpet boot-flow audit."""
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_amonet_crumpet_boot_flow import correlate, source_audit
from test_audit_nand_boot_gpt import synthetic_nand


def create_fake_am(root, lk="expdb", key_return=1, macro=False, loop_break=False,
                   reversed_calls=False):
    files = {
        "include/devices/crumpet.h": (
            '#define PLATFORM mt8516\n'
            f'#define LK_PART_NAME "{lk}"\n'
            + ("#define USB_CABLE_IN_ADDR 0x0020ffff\n" if macro else "")),
        "include/preloader.h": (
            "static inline int usb_cable_in(void) { return 1; }\n"),
        "devices/crumpet.c": (
            "uint8_t usbdl_detect_key(void) {\n"
            "  // Force hacked USB download during bring-up\n"
            f"  return {key_return};\n" "}\n"),
        "usbdl.c": (
            "static void do_usb_handshake(void) {\n"
            "  while (1) { usb_handshake(); "
            + ("break;" if loop_break else "mdelay(2500);")
            + " }\n}\n"
            "void enter_usbdl(uint8_t force) {\n"
            "  if (force || (usb_cable_in() && usbdl_detect_key()))"
            " { do_usb_handshake(); }\n}\n"),
        "main.c": (
            "int main(void) {\n"
            "  // enter_usbdl() appears in a comment before real call.\n"
            "  apply_patches();\n"
            "  setup_usb_descriptors();\n"
            "  boot_device_init();\n"
            + (
                "  bldr_load_part(LK_PART_NAME, 0, 0, 0);\n"
                "  enter_usbdl(0);\n"
                if reversed_calls else
                "  enter_usbdl(0);\n"
                "  bldr_load_part(LK_PART_NAME, 0, 0, 0);\n"
            )
            + "  return -1;\n}\n"),
        "build.sh": 'DONOR="tees/tee_$DEVICE.img"\n',
        "platform/mt8516/include/platform.h": "#define PLATFORM_NAME mt8516\n",
    }
    for path, content in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def definite_dead_end(result):
    return (
        not result["usb_cable_macro_defined"] and
        result["usb_fallback_always_true"] and
        result["usb_key_always_true"] and
        result["handshake_loop_no_source_exit"] and
        result["usb_gate_matches_source"] and
        result["enter_calls_handshake"] and
        result["normal_enter_before_lk_load"])


class AmonetBootFlowTests(unittest.TestCase):
    def test_crumpet_default_path_never_reaches_lk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root)
            r = source_audit(root)
            self.assertTrue(definite_dead_end(r))
            self.assertTrue(r["requires_missing_donor"])
            self.assertTrue(r["main_calls_in_expected_order"])

    def test_source_comments_do_not_change_execution_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root, reversed_calls=True)
            r = source_audit(root)
            self.assertFalse(r["normal_enter_before_lk_load"])
            self.assertFalse(definite_dead_end(r))

    def test_explicit_usb_cable_callback_breaks_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root, macro=True)
            r = source_audit(root)
            self.assertTrue(r["usb_cable_macro_defined"])
            self.assertFalse(definite_dead_end(r))

    def test_key_detector_return_false_breaks_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root, key_return=0)
            self.assertFalse(definite_dead_end(source_audit(root)))

    def test_handshake_with_break_is_not_infinite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root, loop_break=True)
            self.assertFalse(definite_dead_end(source_audit(root)))

    def test_gpt_expdb_is_missing_even_if_lk_a_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root)
            r = correlate(root, synthetic_nand())
            self.assertEqual(r["gpt_entry_count"], 5)
            self.assertFalse(r["lk_partition_in_gpt"])

    def test_referencing_real_partition_name_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root, lk="lk_a")
            self.assertTrue(correlate(root, synthetic_nand())["lk_partition_in_gpt"])

    def test_present_donor_does_not_fix_source_dead_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_fake_am(root)
            donor = root / "tees/tee_crumpet.img"
            donor.parent.mkdir(exist_ok=True)
            donor.write_bytes(b"synthetic placeholder, NOT a functional TEE")
            r = source_audit(root)
            self.assertFalse(r["requires_missing_donor"])
            self.assertTrue(definite_dead_end(r))


if __name__ == "__main__":
    unittest.main()

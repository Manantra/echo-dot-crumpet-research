"""Manufactured ARM/Thumb code and pointer fixtures; NO vendor binaries."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da2_bootstrap_contract import (
    KNOWN, MAGIC_ARGUMENT, MAGIC_PROTOCOL, ROM_BASE, SYNC,
    ascii_at, branch_target, entry_pointer_contract,
    expect, instruction, pc_literal, verify_binary, word,
)


def fake_arm_entry():
    body = bytearray(0x140)
    struct.pack_into("<I", body, 0x24, 0xE59F60D0)
    struct.pack_into("<I", body, 0x28, 0xE5860000)
    struct.pack_into("<I", body, 0xF8, 0xEAFFFFFE)
    struct.pack_into("<I", body, 0xFC, ROM_BASE + 0x20)
    return body


class BootstrapContractTests(unittest.TestCase):
    def test_arm_entry_saves_incoming_r0_to_header_slot(self):
        self.assertEqual(entry_pointer_contract(bytes(fake_arm_entry())),
                         ROM_BASE + 0x20)

    def test_changed_argument_slot_rejected(self):
        d = fake_arm_entry()
        struct.pack_into("<I", d, 0xFC, ROM_BASE + 0x24)
        with self.assertRaisesRegex(ValueError, "slot literal changed"):
            entry_pointer_contract(bytes(d))

    def test_preexisting_nonzero_pointer_rejected(self):
        d = fake_arm_entry()
        struct.pack_into("<I", d, 0x20, 0xDEADBEEF)
        with self.assertRaisesRegex(ValueError, "empty stored-image"):
            entry_pointer_contract(bytes(d))

    def test_changed_arm_prologue_rejected(self):
        d = fake_arm_entry()
        struct.pack_into("<I", d, 0x28, 0xE1A00000)
        with self.assertRaisesRegex(ValueError, "Unexpected instruction"):
            entry_pointer_contract(bytes(d))

    def test_branch_must_self_loop(self):
        d = fake_arm_entry()
        struct.pack_into("<I", d, 0xF8, 0xE1A00000)
        with self.assertRaisesRegex(ValueError, "Unexpected instruction"):
            entry_pointer_contract(bytes(d))

    def test_synthetic_thumb_pc_literal(self):
        d = bytearray(0x300)
        # Thumb LDR R3, [PC,#0]; literal is at PC+4.
        d[0x200:0x202] = b"\x00\x4b"
        struct.pack_into("<I", d, 0x204, MAGIC_ARGUMENT)
        self.assertEqual(pc_literal(bytes(d), ROM_BASE+0x200),
                         MAGIC_ARGUMENT)

    def test_thumb_literal_bad_opcode_fails_closed(self):
        d = bytearray(0x300)
        d[0x200:0x202] = b"\x00\x20"  # movs r0,0, not ldr
        with self.assertRaisesRegex(ValueError, "Not a Thumb"):
            pc_literal(bytes(d), ROM_BASE+0x200)

    def test_thumb_immediate_branch_to_same_pc(self):
        d = bytearray(0x300)
        d[0x240:0x242] = b"\xfe\xe7"  # b . in Thumb
        self.assertEqual(branch_target(bytes(d), ROM_BASE+0x240, "b"),
                         ROM_BASE+0x240)

    def test_nonprintable_string_rejected(self):
        d = bytearray(0x300)
        d[0x270:0x275] = b"A\x01B\x00X"
        with self.assertRaisesRegex(ValueError, "printable"):
            ascii_at(bytes(d), ROM_BASE+0x270)

    def test_copy_helper_opcode_must_match_requested_arm_mode(self):
        d = bytearray(0x300)
        struct.pack_into("<I", d, 0x210, 0xE3520000)  # cmp r2, #0 ARM
        self.assertEqual(expect(bytes(d), ROM_BASE+0x210,
                                "cmp", "r2, #0", thumb=False).mnemonic, "cmp")

    def test_unpinned_file_rejected_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"MTK_DA_V5.bin").write_bytes(b"manufactured fake loader")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_binary({"filename": "MTK_DA_V5.bin"}, root)

    def test_known_fingerprints_and_status_constants(self):
        self.assertEqual(len(KNOWN), 2)
        self.assertEqual(MAGIC_ARGUMENT, 0xFE4A4D42)
        self.assertEqual(MAGIC_PROTOCOL, 0xFEEEEEEF)
        self.assertEqual(SYNC, 0x434E5953)
        self.assertNotEqual(KNOWN["MTK_DA_V5.bin"]["copy_size"],
                            KNOWN["MTK_AllInOne_DA_mt6590.bin"]["copy_size"])

    def test_code_bounds_fail_closed(self):
        d = bytes(fake_arm_entry())
        with self.assertRaisesRegex(ValueError, "outside body"):
            instruction(d, ROM_BASE+0x500)
        with self.assertRaisesRegex(ValueError, "outside firmware"):
            word(d, ROM_BASE+0x500)


if __name__ == "__main__":
    unittest.main()

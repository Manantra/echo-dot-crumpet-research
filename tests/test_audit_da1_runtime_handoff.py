"""Manufactured instruction and argument-layout tests: no MTK binary bytes."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_da1_runtime_handoff import (
    DA1_LOAD_BASE, DA1_PROFILES, audit_da1, expect_thumb,
    thumb_instruction, thumb_literal, transfer_size,
)


def manufactured_da1():
    return bytearray(0x500)


def put(body, address, payload):
    at = address - DA1_LOAD_BASE
    body[at:at + len(payload)] = payload


def pair_sequence():
    # These standard Thumb16/Thumb32 opcodes are manufactured:
    # ldmia r5!,{r0-r3}, stmia r4!,{r0-r3},
    # ldm.w r5,{r0,r1}, stm.w r4,{r0,r1}.
    return [
        (DA1_LOAD_BASE + 0x100, "ldm", 4),
        (DA1_LOAD_BASE + 0x102, "stm", 4),
        (DA1_LOAD_BASE + 0x104, "ldm.w", 2),
        (DA1_LOAD_BASE + 0x108, "stm.w", 2),
    ]


def manufactured_copy():
    b = manufactured_da1()
    put(b, DA1_LOAD_BASE + 0x100, bytes.fromhex("0fcd0fc495e8030084e80300"))
    return bytes(b)


class Da1ParamContractTests(unittest.TestCase):
    def test_manufactured_first_segment_is_24_bytes(self):
        self.assertEqual(transfer_size(manufactured_copy(), pair_sequence()), 24)

    def test_da1_thumb_literal_at_correct_pc_alignment(self):
        b = manufactured_da1()
        # Thumb 16-bit ldr r3,[pc,#0] at 0x200102, literal aligned at 0x200104.
        put(b, DA1_LOAD_BASE + 0x102, b"\x00\x4b")
        struct.pack_into("<I", b, 0x104, 0xFE4A4D42)
        self.assertEqual(thumb_literal(bytes(b), DA1_LOAD_BASE + 0x102),
                         0xFE4A4D42)

    def test_non_pc_load_rejected(self):
        b = manufactured_da1()
        put(b, DA1_LOAD_BASE + 0x102, bytes.fromhex("1068"))
        with self.assertRaisesRegex(ValueError, "Thumb literal LDR"):
            thumb_literal(bytes(b), DA1_LOAD_BASE + 0x102)

    def test_out_of_range_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            thumb_instruction(bytes(manufactured_da1()), DA1_LOAD_BASE - 2)

    def test_wrong_copy_opcode_rejected(self):
        b = bytearray(manufactured_copy())
        put(b, DA1_LOAD_BASE + 0x100, bytes.fromhex("0020"))
        with self.assertRaisesRegex(ValueError, "Opcode mismatch"):
            transfer_size(bytes(b), pair_sequence())

    def test_wrong_register_count_rejected(self):
        b = bytearray(manufactured_copy())
        put(b, DA1_LOAD_BASE + 0x100, bytes.fromhex("03cd"))
        with self.assertRaisesRegex(ValueError, "register list"):
            transfer_size(bytes(b), pair_sequence())

    def test_unmatched_source_destination_counts_rejected(self):
        b = manufactured_copy()
        seq = pair_sequence()[:-1]
        with self.assertRaisesRegex(ValueError, "counts differ"):
            transfer_size(b, seq)

    def test_thumb_mov_and_indirect_blx_are_distinct(self):
        b = manufactured_da1()
        put(b, DA1_LOAD_BASE + 0x110, bytes.fromhex("3046c047"))
        self.assertEqual(expect_thumb(bytes(b), DA1_LOAD_BASE + 0x110,
                                      "mov", "r0, r6").mnemonic, "mov")
        self.assertEqual(expect_thumb(bytes(b), DA1_LOAD_BASE + 0x112,
                                      "blx", "r8").mnemonic, "blx")

    def test_original_da_profiles_have_distinct_layouts(self):
        a = DA1_PROFILES["MTK_DA_V5.bin"]
        b = DA1_PROFILES["MTK_AllInOne_DA_mt6590.bin"]
        self.assertEqual((a["first_copy_size"], a["second_copy_size"]),
                         (24, 56))
        self.assertEqual((b["first_copy_size"], b["second_copy_size"]),
                         (24, 32))
        self.assertEqual(8 + 24 + 56, 88)
        self.assertEqual(8 + 24 + 32, 64)
        self.assertNotEqual(a["runtime_dst"], b["runtime_dst"])

    def test_full_struct_layout_requires_original_instructions(self):
        # Fake DA1 must not be accepted as a pinned original instruction map.
        with self.assertRaises((ValueError, RuntimeError)):
            audit_da1(bytes(manufactured_da1()),
                      DA1_PROFILES["MTK_DA_V5.bin"])


if __name__ == "__main__":
    unittest.main()

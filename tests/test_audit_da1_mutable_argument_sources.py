"""Synthetic DA1 runtime source pointers; no proprietary image bytes."""
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_da1_mutable_argument_sources as mod

V5 = "MTK_DA_V5.bin"
ALT = "MTK_AllInOne_DA_mt6590.bin"


def manufacture(name):
    p = mod.DA1_PROFILES[name]
    r = mod.LITERAL_SITES[name]
    data = bytearray(2048)
    for i in range(r["first_source_occurrences"]):
        struct.pack_into("<I", data, i * 8, p["first_source"])
    for i in range(r["second_source_occurrences"]):
        struct.pack_into("<I", data, 256 + i * 8, p["second_source"])
    return bytes(data)


def simulation(name, data=None):
    p = mod.DA1_PROFILES[name]
    r = mod.LITERAL_SITES[name]
    if data is None:
        data = manufacture(name)
    literals = {
        r["first_literal_pc"]: p["first_source"],
        r["second_literal_pc"]: p["second_source"],
        r["status_word_pc"]: p["flag_source"],
        r["second_state_early_pc"]: p["second_source"],
    }
    for ptr_insn, _, _, _, _ in mod.WRITES[name]:
        literals[ptr_insn] = p["second_source"]

    def fake_expect(_body, _addr, mnemonic, operands=None):
        if _addr == r["second_state_early_insn"]:
            text = ("r3, [r3, #8]" if name == V5
                    else "r3, [r5, #0x18]")
            return type("Insn", (), {"op_str": text})()
        return type("Insn", (), {"op_str": operands or "",
                                 "mnemonic": mnemonic})()

    return literals, fake_expect


class MutableStateTests(unittest.TestCase):
    def test_v5_first_source_literal_once_second_sixteen_times(self):
        b = manufacture(V5)
        p = mod.DA1_PROFILES[V5]
        self.assertEqual(len(mod.literal_occurrences(b, p["first_source"])), 1)
        self.assertEqual(len(mod.literal_occurrences(b, p["second_source"])), 16)

    def test_alternative_second_state_literal_ten_times(self):
        b = manufacture(ALT)
        p = mod.DA1_PROFILES[ALT]
        self.assertEqual(len(mod.literal_occurrences(b, p["second_source"])), 10)

    def test_v5_manufactured_cross_reference_and_field_offsets(self):
        lits, mock_expect = simulation(V5)
        with patch.object(mod, "audit_da1", return_value={"total_argument_bytes": 88}), \
             patch.object(mod, "thumb_literal", side_effect=lambda _b, at: lits[at]), \
             patch.object(mod, "expect_thumb", side_effect=mock_expect):
            result = mod.check_mutable_sources(V5, manufacture(V5))
        self.assertEqual(result["second_source_copied_bytes"], 56)
        self.assertEqual(len(result["proven_state_writes"]), 6)
        self.assertEqual(sorted({x["copied_table_field_offset"]
                                 for x in result["proven_state_writes"]}),
                         [0, 8, 16, 20, 28, 36])
        self.assertFalse(result["actual_crumpet_ram_contents_observed"])

    def test_alt_manufactured_four_field_writes(self):
        lits, mock_expect = simulation(ALT)
        with patch.object(mod, "audit_da1", return_value={"total_argument_bytes": 64}), \
             patch.object(mod, "thumb_literal", side_effect=lambda _b, at: lits[at]), \
             patch.object(mod, "expect_thumb", side_effect=mock_expect):
            result = mod.check_mutable_sources(ALT, manufacture(ALT))
        self.assertEqual(result["second_source_copied_bytes"], 32)
        self.assertEqual(len(result["proven_state_writes"]), 4)
        self.assertEqual(sorted(x["copied_table_field_offset"]
                                for x in result["proven_state_writes"]),
                         [12, 20, 24, 28])

    def test_one_removed_second_source_literal_is_detected(self):
        b = bytearray(manufacture(V5))
        b[256:260] = bytes(4)
        with patch.object(mod, "audit_da1",
                          return_value={"total_argument_bytes": 88}), \
             self.assertRaisesRegex(ValueError, "frequency changed"):
            mod.check_mutable_sources(V5, bytes(b))

    def test_corrupt_source_literal_disassembly_is_rejected(self):
        lits, mock_expect = simulation(V5)
        refs = mod.LITERAL_SITES[V5]
        lits[refs["second_literal_pc"]] ^= 4
        with patch.object(mod, "audit_da1", return_value={"total_argument_bytes": 88}), \
             patch.object(mod, "thumb_literal", side_effect=lambda _b, at: lits[at]), \
             patch.object(mod, "expect_thumb", side_effect=mock_expect), \
             self.assertRaisesRegex(ValueError, "second-source instruction"):
            mod.check_mutable_sources(V5, manufacture(V5))

    def test_copied_table_write_beyond_bound_is_rejected(self):
        lits, mock_expect = simulation(ALT)
        bad = (mod.WRITES[ALT][0][0:4] + (0x40,),)
        with patch.dict(mod.WRITES, {ALT: bad}), \
             patch.object(mod, "audit_da1", return_value={"total_argument_bytes": 64}), \
             patch.object(mod, "thumb_literal", side_effect=lambda _b, at: lits[at]), \
             patch.object(mod, "expect_thumb", side_effect=mock_expect), \
             self.assertRaisesRegex(ValueError, "outside copied"):
            mod.check_mutable_sources(ALT, manufacture(ALT))

    def test_mutated_status_control_source_refused(self):
        lits, mock_expect = simulation(V5)
        refs = mod.LITERAL_SITES[V5]
        lits[refs["status_word_pc"]] = 0
        with patch.object(mod, "audit_da1", return_value={"total_argument_bytes": 88}), \
             patch.object(mod, "thumb_literal", side_effect=lambda _b, at: lits[at]), \
             patch.object(mod, "expect_thumb", side_effect=mock_expect), \
             self.assertRaisesRegex(ValueError, "Control status word"):
            mod.check_mutable_sources(V5, manufacture(V5))

    def test_unknown_loader_rejected_before_disassembly(self):
        with self.assertRaisesRegex(ValueError, "Unknown DA1 profile"):
            mod.check_mutable_sources("not_a_DA.bin", bytes(100))

    def test_original_image_not_included_in_fixtures(self):
        self.assertLess(len(manufacture(V5)), 4096)
        self.assertLess(len(manufacture(ALT)), 4096)


if __name__ == "__main__":
    unittest.main()

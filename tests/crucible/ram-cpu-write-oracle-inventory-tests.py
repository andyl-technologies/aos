"""Rejects matched opcode and width substitutions in actual emitted records.

These are static artifact controls; no guest, dirty tracking or VM is executed.
"""

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--inventory-tool", type=Path, required=True)
parser.add_argument("--artifacts", type=Path, required=True)
arguments, remaining = parser.parse_known_args()
specification = importlib.util.spec_from_file_location("inventory", arguments.inventory_tool)
inventory = importlib.util.module_from_spec(specification)
specification.loader.exec_module(inventory)
profiles = json.loads((arguments.artifacts / "manifest.json").read_text())["profiles"]


class EncodingControls(unittest.TestCase):
    def test_all_actual_extended_encodings_match(self):
        for row in profiles[15:]:
            with self.subTest(profile=row["profile"]):
                inventory.require_extended_body(row["index"], row["operation"])

    def test_add_and_xadd_swap_is_rejected_even_with_same_target_and_count(self):
        for index in range(15, 23):
            body = copy.deepcopy(profiles[index]["operation"])
            target = inventory.TARGETS[index][0]
            if index <= 19:
                register = "%al" if index == 15 else "%ax" if index == 16 else "%eax"
                prefixes = [0xf0] + ([0x66] if index >= 17 else [])
                opcode = [0x0f, 0xc0 if index == 15 else 0xc1, 0x06]
                mnemonic = "xadd"
            else:
                register, prefixes, opcode, mnemonic = "%eax", [0xf0, 0x66], [0x01, 0x06], "add"
            body[0] = {"bytes": bytes([*prefixes, *opcode, *target.to_bytes(2, "little")]).hex(" "),
                       "instruction": f"lock {mnemonic} {register},0x{target:x}"}
            with self.subTest(index=index):
                with self.assertRaises(AssertionError):
                    inventory.require_extended_body(index, body)

    def test_real_wrong_width_and_missing_lock_encodings_are_rejected(self):
        for index in range(15, 23):
            target = inventory.TARGETS[index][0]
            body = copy.deepcopy(profiles[index]["operation"])
            is_add = index <= 19
            wide = index in (15, 16)
            register = "%eax" if wide else "%ax"
            prefixes = [0xf0, 0x66] if wide else [0xf0]
            opcode = [0x01, 0x06] if is_add else [0x0f, 0xc1, 0x06]
            body[0] = {"bytes": bytes([*prefixes, *opcode, *target.to_bytes(2, "little")]).hex(" "),
                       "instruction": f"lock {'add' if is_add else 'xadd'} {register},0x{target:x}"}
            with self.subTest(index=index, mutation="width"):
                with self.assertRaises(AssertionError):
                    inventory.require_extended_body(index, body)
            body = copy.deepcopy(profiles[index]["operation"])
            body[0]["bytes"] = body[0]["bytes"].replace("f0 ", "", 1)
            body[0]["instruction"] = body[0]["instruction"].removeprefix("lock ")
            with self.subTest(index=index, mutation="lock"):
                with self.assertRaises(AssertionError):
                    inventory.require_extended_body(index, body)

    def test_cas_operand_width_is_bound_independently_of_final_byte_values(self):
        for index in range(23, 27):
            body = copy.deepcopy(profiles[index]["operation"])
            target = inventory.TARGETS[index][0]
            prefixes = [0xf0] if index <= 24 else [0x66, 0xf0]
            register = "%cx" if index <= 24 else "%ecx"
            body[-1] = {"bytes": bytes([*prefixes, 0x0f, 0xb1, 0x0e,
                                       *target.to_bytes(2, "little")]).hex(" "),
                        "instruction": f"lock cmpxchg {register},0x{target:x}"}
            with self.subTest(index=index):
                with self.assertRaises(AssertionError):
                    inventory.require_extended_body(index, body)

    def test_compound_second_address_width_and_complement_are_mandatory(self):
        for position in (0, 1, 2):
            body = copy.deepcopy(profiles[27]["operation"])
            encoded = bytearray.fromhex(body[position]["bytes"])
            encoded[-1] ^= 1
            body[position]["bytes"] = encoded.hex(" ")
            with self.subTest(position=position):
                with self.assertRaises(AssertionError):
                    inventory.require_extended_body(27, body)


if __name__ == "__main__":
    unittest.main(argv=[__file__, *remaining])

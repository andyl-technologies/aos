# SPDX-License-Identifier: Apache-2.0
"""Checks geometry admission; synthetic disassembly does not qualify a VM."""

import importlib.util
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "byte_asset", pathlib.Path(__file__).with_name("ram-byte-service-asset.py")
)
ASSET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSET)


class ByteAssetGeometryTests(unittest.TestCase):
    def setUp(self):
        self.symbols = {"long_mode": 0x100000, "aligned_target": 0x102000, "aligned_result": 0x102100}
        self.instructions = [
            (0x100000, b"\x90", "nop", ""),
            (0x100010, b"\xf3\x90", "pause", ""),
            (0x100012, b"\xe2\xfc", "loop", "100010 <long_mode+0x10>"),
            (0x100014, b"\x8a\x04\x25\x00\x20\x10\x00", "mov", "0x102000,%al"),
            (0x10001b, b"\x88\x04\x25\x00\x21\x10\x00", "mov", "%al,0x102100"),
        ]

    def test_checked_pair_preserves_load_coordinates_and_adds_store(self):
        coordinates = dict(ASSET.derive_coordinates(self.symbols, self.instructions))
        self.assertEqual(coordinates, {
            "CRUCIBLE_BYTE_ENTRY": 0x100000,
            "CRUCIBLE_BYTE_DELAY_START": 0x100010,
            "CRUCIBLE_BYTE_DELAY_END": 0x100014,
            "CRUCIBLE_BYTE_TARGET": 0x102000,
            "CRUCIBLE_BYTE_STORE_PC": 0x10001b,
            "CRUCIBLE_BYTE_RESULT": 0x102100,
        })

    def test_missing_store_refuses(self):
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions[:-1])

    def test_different_store_opcode_refuses(self):
        self.instructions[-1] = (0x10001b, b"\x89\x04\x25\x00\x21\x10\x00", "mov", "")
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions)

    def test_wrong_store_symbol_refuses(self):
        self.symbols["aligned_result"] += 1
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions)

    def test_nonadjacent_store_refuses(self):
        address, encoded, mnemonic, operand = self.instructions[-1]
        self.instructions[-1] = (address + 1, encoded, mnemonic, operand)
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions)

    def test_wrong_load_symbol_still_refuses(self):
        self.symbols["aligned_target"] += 1
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions)

    def test_result_outside_supported_identity_mapping_refuses(self):
        self.symbols["aligned_result"] = 0x200000
        self.instructions[-1] = (0x10001b, b"\x88\x04\x25\x00\x00\x20\x00", "mov", "")
        with self.assertRaises(ValueError):
            ASSET.derive_coordinates(self.symbols, self.instructions)

    def test_missing_or_duplicate_result_symbol_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "symbols.txt"
            prefix = "00100000 t long_mode\n00102000 d aligned_target\n"
            for suffix in ("", "00102100 d aligned_result\n00102100 d aligned_result\n"):
                path.write_text(prefix + suffix)
                with self.assertRaises(ValueError):
                    ASSET.read_symbols(path)


if __name__ == "__main__":
    unittest.main()

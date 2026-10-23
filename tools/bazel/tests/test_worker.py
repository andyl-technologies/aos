"""Checks the boundary between public exports and bindgen's private indices."""

import unittest

from verify_worker import public_exports


class WorkerExportTests(unittest.TestCase):
    def test_numbered_trampolines_allow_numeric_collision_suffixes(self):
        exports = {
            "memory": "memory",
            "fetch": "function",
            "__wasm_bindgen_func_elem_1413": "function",
            "__wasm_bindgen_func_elem_1413_2": "function",
        }
        self.assertEqual(public_exports(exports), {"memory": "memory", "fetch": "function"})

    def test_other_exports_remain_part_of_the_contract(self):
        exports = {
            "__wasm_bindgen_func_elem_named": "function",
            "__wasm_bindgen_func_elem_1413_helper": "function",
            "__wasm_bindgen_func_elem_1413_2_extra": "function",
            "__wbindgen_malloc": "function",
        }
        self.assertEqual(public_exports(exports), exports)

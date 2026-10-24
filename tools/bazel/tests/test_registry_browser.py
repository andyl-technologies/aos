"""Keeps generated binding signatures exact across compiler crate identities."""

import unittest

from verify_registry_browser import binding_export_contract


class RegistryBindingExportTests(unittest.TestCase):
    def setUp(self):
        self.symbol = (
            "wasm_bindgen_0123456789abcdef___convert__closures_____invoke___"
            "js_sys_0123456789abcdef___Function_fn_wasm_bindgen_0123456789abcdef___JsValue______true__2"
        )

    def test_only_generated_closure_crate_identities_are_normalized(self):
        other = self.symbol.replace("0123456789abcdef", "fedcba9876543210")
        self.assertEqual(binding_export_contract({self.symbol: "function"}),
                         binding_export_contract({other: "function"}))
        for changed in [self.symbol.replace("JsValue", "JsError"), self.symbol.removesuffix("__2")]:
            self.assertNotEqual(binding_export_contract({self.symbol: "function"}),
                                binding_export_contract({changed: "function"}))

        ordinary = "public_0123456789abcdef"
        self.assertEqual(binding_export_contract({ordinary: "function"}), {ordinary: "function"})

    def test_colliding_export_normalization_fails_closed(self):
        other = self.symbol.replace("0123456789abcdef", "fedcba9876543210")
        with self.assertRaisesRegex(ValueError, "merged distinct symbols"):
            binding_export_contract({self.symbol: "function", other: "function"})

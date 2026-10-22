"""Exercises editor qualification failures that would hide missing Rust views."""

import copy
from pathlib import Path
import tempfile
import unittest

from verify_family_editor import analysis_statistics, verify


class FamilyEditorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in ["crates/device/src/lib.rs", "crates/device/tests/io.rs", "core/src/lib.rs"]:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.touch()
        self.packages = {"device": "crates/device"}
        self.inventory = {"configured_targets": [
            {"label": "//crates/device:lib", "kind": "rust_library", "features": ["default"]},
            {"label": "//crates/device:io_binary", "kind": "rust_test", "features": ["default"]},
        ]}
        self.project = {"sysroot_src": str(self.root), "crates": [
            {"root_module": str(self.root / path), "is_proc_macro": False, "cfg": ['feature="default"']}
            for path in ["crates/device/src/lib.rs", "crates/device/tests/io.rs"]
        ]}

    def test_matching_library_and_integration_views_pass(self):
        report = verify(self.project, self.inventory, self.packages, self.root)
        self.assertEqual(len(report["roots"]), 2)

    def test_missing_integration_view_fails(self):
        self.project["crates"].pop()
        with self.assertRaisesRegex(ValueError, "root or feature mismatch"):
            verify(self.project, self.inventory, self.packages, self.root)

    def test_different_editor_features_fail(self):
        self.project["crates"][0]["cfg"] = []
        with self.assertRaisesRegex(ValueError, "root or feature mismatch"):
            verify(self.project, self.inventory, self.packages, self.root)

    def test_duplicate_variant_fails(self):
        self.project["crates"].append(copy.deepcopy(self.project["crates"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate editor root"):
            verify(self.project, self.inventory, self.packages, self.root)

    def test_missing_proc_macro_fails(self):
        self.project["crates"].append({
            "root_module": str(self.root / "core/src/lib.rs"), "display_name": "derive",
            "is_proc_macro": True, "proc_macro_dylib_path": str(self.root / "missing.so"),
        })
        with self.assertRaisesRegex(ValueError, "proc macro does not exist"):
            verify(self.project, self.inventory, self.packages, self.root)

    def test_incomplete_inference_is_reported_without_claiming_parity(self):
        report = analysis_statistics(
            "exprs: 100, ??ty: 12 (12%), ?ty: 16 (16%)\n"
            "pats: 10, ??ty: 0 (0%), ?ty: 0 (0%)\n  panics: 0\n"
        )
        self.assertFalse(report["complete_inference"])
        self.assertEqual(report["exprs"]["unknown"], 12)

    def test_analyzer_panic_fails_even_with_inference_summary(self):
        with self.assertRaisesRegex(ValueError, "without panics"):
            analysis_statistics(
                "exprs: 10, ??ty: 0 (0%), ?ty: 0 (0%)\n"
                "pats: 10, ??ty: 0 (0%), ?ty: 0 (0%)\n  panics: 1\n"
            )


if __name__ == "__main__":
    unittest.main()

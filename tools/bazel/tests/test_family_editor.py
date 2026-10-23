"""Exercises editor qualification failures that would hide missing Rust views."""

import copy
from pathlib import Path
import tempfile
import unittest

from verify_family_editor import analysis_statistics, compare_analysis, diagnostics, verify


class EditorComparisonTests(unittest.TestCase):
    def setUp(self):
        self.packages = {"guest": "crates/guest"}
        self.row = ["crates/guest/src/lib.rs", "1:0", "1:2", "type", "{unknown}"]
        self.bazel = {"analysis": {"panics": 0, "exprs": {"total": 10}},
                      "diagnostics": [self.row], "roots": {"crates/guest/src/lib.rs": []}}
        self.cargo = {"panics": 0, "exprs": {"total": 20}, "diagnostics": [self.row, [
            "crates/dependency/src/lib.rs", "2:0", "2:2", "type", "{unknown}",
        ]]}

    def test_scoped_comparison_retains_both_statistics_and_unselected_diagnostics(self):
        report = compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")
        self.assertFalse(report["aggregate_statistics_comparable"])
        self.assertEqual(report["analysis"]["exprs"]["total"], 10)
        self.assertEqual(report["cargo_analysis"]["exprs"]["total"], 20)
        self.assertEqual(report["diagnostics"], [self.row])
        self.assertEqual(report["unselected_cargo_diagnostics"], self.cargo["diagnostics"][1:])

    def test_owned_diagnostic_regressions_and_unexpected_bazel_scope_fail(self):
        self.bazel["diagnostics"] = []
        with self.assertRaisesRegex(ValueError, "diagnostic locations or types differ"):
            compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")
        self.bazel["diagnostics"] = self.cargo["diagnostics"]
        with self.assertRaisesRegex(ValueError, "outside the selected family"):
            compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")

    def test_unattributed_cargo_diagnostics_are_retained_and_bazel_ones_fail(self):
        synthetic = ["synthetic", "", "", "type", "{unknown}"]
        self.cargo["diagnostics"].extend([synthetic, synthetic])

        report = compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")

        self.assertEqual(report["diagnostics"], [self.row])
        self.assertEqual(report["unattributed_cargo_diagnostics"], [synthetic, synthetic])
        self.assertEqual(len(report["unselected_cargo_diagnostics"]), 1)
        self.bazel["diagnostics"].append(synthetic)
        with self.assertRaisesRegex(ValueError, "outside the selected family"):
            compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")

    def test_whole_model_comparison_still_requires_equal_statistics(self):
        with self.assertRaisesRegex(ValueError, "editor inference differs"):
            compare_analysis(self.bazel, self.cargo, self.packages)
        self.cargo["panics"] = 1
        with self.assertRaisesRegex(ValueError, "without panics"):
            compare_analysis(self.bazel, self.cargo, self.packages, "selected-packages")


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
            {"label": "//crates/device:lib", "kind": "rust_library", "features": ["default"], "crate_root": "crates/device/src/lib.rs"},
            {"label": "//crates/device:io_binary", "kind": "rust_test", "features": ["default"], "crate_root": "crates/device/tests/io.rs"},
        ]}
        self.project = {"sysroot_src": str(self.root), "crates": [
            {"root_module": str(self.root / path), "is_proc_macro": False, "cfg": ['feature="default"']}
            for path in ["crates/device/src/lib.rs", "crates/device/tests/io.rs"]
        ]}

    def test_matching_library_and_integration_views_pass(self):
        report = verify(self.project, self.inventory, self.packages, self.root)
        self.assertEqual(len(report["roots"]), 2)

    def test_binary_and_libtest_share_the_declared_source_root(self):
        root = "crates/device/src/bin/tool.rs"
        (self.root / root).parent.mkdir(parents=True)
        (self.root / root).touch()
        for name, kind in [("tool", "rust_binary"), ("bin_tool_binary", "rust_test")]:
            self.inventory["configured_targets"].append({
                "label": "//crates/device:" + name, "kind": kind,
                "features": ["default"], "crate_root": root,
            })
        self.project["crates"].append({
            "root_module": str(self.root / root), "is_proc_macro": False, "cfg": ['feature="default"'],
        })

        report = verify(self.project, self.inventory, self.packages, self.root)

        self.assertEqual(len(report["roots"]), 3)

    def test_invented_or_outside_compiled_root_fails(self):
        for root in ["crates/device/tests/missing.rs", "core/src/lib.rs"]:
            with self.subTest(root=root):
                self.inventory["configured_targets"][0]["crate_root"] = root
                with self.assertRaisesRegex(ValueError, "compiled crate root"):
                    verify(self.project, self.inventory, self.packages, self.root)

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

    def test_dependency_library_can_share_its_separate_libtest_root(self):
        library = copy.deepcopy(self.project["crates"][0])
        library["is_workspace_member"] = False
        self.project["crates"].insert(0, library)

        report = verify(self.project, self.inventory, self.packages, self.root)

        self.assertEqual(len(report["roots"]), 2)

    def test_dependency_library_still_requires_matching_compiled_features(self):
        library = copy.deepcopy(self.project["crates"][0])
        library.update(is_workspace_member=False, cfg=[])
        self.project["crates"].append(library)

        with self.assertRaisesRegex(ValueError, "root or feature mismatch"):
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

    def test_diagnostics_preserve_locations_types_and_multiplicity_across_worktrees(self):
        first = self.root / "first.csv"
        second = self.root / "second.csv"
        first.write_text('/build/bazel/crates/device/src/lib.rs,1:2,1:4,type,"{unknown}"\n' * 2)
        second.write_text('/build/cargo/crates/device/src/lib.rs,1:2,1:4,type,"{unknown}"\n' * 2)
        self.assertEqual(diagnostics(first), diagnostics(second))
        self.assertEqual(len(diagnostics(first)), 2)

        second.write_text('/build/cargo/crates/device/src/lib.rs,2:2,2:4,type,"{unknown}"\n')
        self.assertNotEqual(diagnostics(first), diagnostics(second))


if __name__ == "__main__":
    unittest.main()

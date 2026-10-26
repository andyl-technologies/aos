"""Checks source discovery roots and declaration fingerprints."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/export_inventory.py"
spec = importlib.util.spec_from_file_location("export_inventory", path)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        for name, contents in {
            "MODULE.bazel": "module(name = 'example')\n",
            "MODULE.bazel.lock": "{}\n",
            "crates/example/BUILD.bazel": "# source graph\n",
            "crates/example/src/lib.rs": "pub fn example() {}\n",
            "docs/unrelated.md": "not a compilation input\n",
        }.items():
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(contents)
        self.reports = [{
            "schema_version": 1, "label": "//crates/example:library",
            "build_file": "crates/example/BUILD.bazel", "kind": "rust_library",
            "sources": ["crates/example/src/lib.rs"], "target_cpu": "x86_64",
            "generated_inputs": {"bazel-out/generated.rs": "//generator:rust"},
        }]

    def inventory(self):
        return exporter.inventory(self.root, ["//crates/example:library"], self.reports)

    def test_declarations_change_contract_implementation_bytes_do_not(self):
        before = self.inventory()
        (self.root / "crates/example/src/lib.rs").write_text("pub fn changed() {}\n")
        (self.root / "docs/unrelated.md").write_text("edited unrelated documentation\n")
        self.assertEqual(before, self.inventory())
        (self.root / "crates/example/BUILD.bazel").write_text("# new dependency\n")
        self.assertNotEqual(before["contracts"], self.inventory()["contracts"])

    def test_new_sources_have_discovery_roots_without_generated_outputs(self):
        result = self.inventory()
        self.assertEqual(result["source_directories"], ["crates/example/src"])
        self.assertEqual(result["source_files"], ["crates/example/src/lib.rs"])
        self.assertNotIn("docs/unrelated.md", result["contracts"])
        self.assertNotIn("bazel-out/generated.rs", result["source_files"])

    def test_missing_target_and_foreign_source_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "omitted"):
            exporter.inventory(self.root, ["//omitted:target"], self.reports)
        self.reports[0]["sources"] = ["../outside.rs"]
        with self.assertRaisesRegex(ValueError, "non-workspace"):
            self.inventory()

    def test_exported_file_retains_its_owning_build_package(self):
        tools = self.root / "tools/example"
        tools.mkdir(parents=True)
        (tools / "BUILD.bazel").write_text('exports_files(["runner.py"])\n')
        (tools / "runner.py").write_text("pass\n")
        self.reports[0]["sources"].append("tools/example/runner.py")
        self.assertIn("tools/example/BUILD.bazel", self.inventory()["contracts"])

    def test_module_includes_and_loaded_definitions_are_contracts(self):
        (self.root / "MODULE.bazel").write_text('include("//crates/example:deps.MODULE.bazel")\n')
        (self.root / "crates/example/deps.MODULE.bazel").write_text("# immutable repositories\n")
        (self.root / "crates/example/macros.bzl").write_text("# shared declarations\n")

        result = exporter.inventory(
            self.root, ["//crates/example:library"], self.reports,
            declarations=["crates/example/macros.bzl"],
        )

        self.assertIn("crates/example/deps.MODULE.bazel", result["contracts"])
        self.assertIn("crates/example/macros.bzl", result["contracts"])

    def test_new_shared_imports_and_transitive_relative_loads_are_fingerprinted(self):
        package = self.root / "crates/example"
        (package / "BUILD.bazel").write_text('load(":aliases.bzl", "CRATES")\n')
        (package / "aliases.bzl").write_text('load("//deps:nested/actual.bzl", "CRATES")\n')
        (self.root / "deps/nested").mkdir(parents=True)
        (self.root / "deps/BUILD.bazel").write_text("# dependency package\n")
        (self.root / "deps/nested/actual.bzl").write_text('load(":shared.bzl", "CRATES")\n')
        shared = self.root / "deps/shared.bzl"
        shared.write_text("CRATES = {}\n")

        before = self.inventory()

        for name in ["crates/example/aliases.bzl", "deps/BUILD.bazel", "deps/nested/actual.bzl", "deps/shared.bzl"]:
            self.assertIn(name, before["contracts"])
        shared.write_text('CRATES = {"new": "dependency"}\n')
        self.assertNotEqual(before["contracts"], self.inventory()["contracts"])

    def test_import_cycles_terminate_and_strings_comments_and_external_loads_are_ignored(self):
        package = self.root / "crates/example"
        (package / "BUILD.bazel").write_text('load(":macros.bzl", "rule")\n')
        (package / "macros.bzl").write_text(
            '\'\'\'Example:\nload("//absent:example.bzl", "example")\n\'\'\'\n'
            '# load(":absent.bzl", "comment")\n'
            'load("@external//:rules.bzl", "external")\n'
            'load(":macros.bzl", "cycle")\n'
        )

        self.assertIn("crates/example/macros.bzl", self.inventory()["contracts"])

    def test_missing_and_escaping_local_loads_fail_closed(self):
        build = self.root / "crates/example/BUILD.bazel"
        for label, diagnostic in [(":missing.bzl", "missing local"), (":../outside.bzl", "invalid local")]:
            with self.subTest(label=label):
                build.write_text(f'load("{label}", "rule")\n')
                with self.assertRaisesRegex(ValueError, diagnostic):
                    self.inventory()


if __name__ == "__main__":
    unittest.main()

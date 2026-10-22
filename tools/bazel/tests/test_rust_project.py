"""Checks that editor export preserves the configured Rust graph."""

import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
from export_rust_project import assemble, compiler_file_lines, current_specs


def spec(name, **overrides):
    value = {
        "crate_id": name, "display_name": name, "edition": "2024",
        "root_module": "__WORKSPACE__/" + name + "/lib.rs",
        "target": "x86_64-unknown-linux-gnu", "env": {},
        "cfg": ["test", "debug_assertions"], "deps": [], "aliases": {},
        "crate_type": "rlib", "is_test": False, "is_workspace_member": True,
        "source": {"include_dirs": [], "exclude_dirs": []},
    }
    value.update(overrides)
    return value


class RustProjectTests(unittest.TestCase):
    def assemble(self, specs):
        return assemble(specs, {"__WORKSPACE__/": Path("/checkout"),
                               "__EXEC_ROOT__/": Path("/exec")}, Path("/toolchain"))

    def test_alias_generated_source_and_proc_macro_are_retained(self):
        macro = spec("macro", crate_type="proc-macro",
                     proc_macro_dylib_path="__EXEC_ROOT__/libmacro.so")
        generated = spec("generated", root_module="__EXEC_ROOT__/generated.rs")
        app = spec("app", deps=["macro", "generated"], aliases={"generated": "renamed"})

        crates = self.assemble([macro, generated, app])["crates"]
        by_name = {crate["display_name"]: crate for crate in crates}

        dependency = next(dep for dep in by_name["app"]["deps"] if dep["name"] == "renamed")
        self.assertEqual(crates[dependency["crate"]]["root_module"], "/exec/generated.rs")
        self.assertEqual(by_name["macro"]["proc_macro_dylib_path"], "/exec/libmacro.so")
        self.assertTrue(by_name["macro"]["is_proc_macro"])
        self.assertNotIn("runnables", by_name["app"])

    def test_libtest_additional_dependencies_merge_without_duplicate_roots(self):
        library = spec("library", env={"ZERO_AR_DATE": "1"})
        test = spec("library", is_test=True, crate_type="bin", deps=["dev"])
        original = copy.deepcopy(test)

        crates = self.assemble([library, test, spec("dev")])["crates"]

        self.assertEqual(len(crates), 2)
        self.assertEqual(len(next(crate for crate in crates if crate["display_name"] == "library")["deps"]), 1)
        self.assertEqual(test, original)
        self.assertEqual(next(crate for crate in crates if crate["display_name"] == "library")["env"], {})

    def test_proc_macro_library_kind_survives_both_test_discovery_orders(self):
        macro = spec("macro", crate_type="proc-macro", proc_macro_dylib_path="__EXEC_ROOT__/macro.so")
        test = spec("macro", is_test=True, crate_type="bin")
        for specs in [[macro, test], [test, macro], [macro, test, test]]:
            with self.subTest(order=[item["crate_type"] for item in specs]):
                crates = self.assemble(specs)["crates"]
                self.assertEqual(len(crates), 1)
                self.assertTrue(crates[0]["is_proc_macro"])
                self.assertEqual(crates[0]["proc_macro_dylib_path"], "/exec/macro.so")

    def test_compiler_environment_paths_use_the_declared_execution_root(self):
        project = self.assemble([spec("lib", env={"CARGO_MANIFEST_DIR": "${pwd}/package"})])
        self.assertEqual(project["crates"][0]["env"]["CARGO_MANIFEST_DIR"], "/exec/package")

    def test_ordinary_crate_roots_include_their_child_module_directory(self):
        project = self.assemble([spec("nested")])
        self.assertEqual(project["crates"][0]["source"]["include_dirs"], ["/checkout/nested"])

    def test_generated_source_directories_are_preserved(self):
        project = self.assemble([spec("generated", source={
            "include_dirs": ["__WORKSPACE__/source", "__EXEC_ROOT__/generated"], "exclude_dirs": [],
        })])
        self.assertEqual(project["crates"][0]["source"]["include_dirs"], ["/checkout/source", "/exec/generated"])

    def test_build_script_cfg_and_environment_match_compiler_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "flags").write_text('--cfg=generated_api\n--cfg=feature="generated"\n-lnative\n')
            (root / "first.env").write_text("VALUE=first\nPATH=${pwd}/input\n")
            (root / "second.env").write_text("VALUE=second=with-equals\nGENERATED=${out_dir}/api.rs\nOUT_DIR=ignored\n")
            crate = spec("lib", aos_build_script_flags="__EXEC_ROOT__/flags",
                         aos_rustc_env_files=["__EXEC_ROOT__/first.env", "__EXEC_ROOT__/second.env"],
                         aos_out_dir="__EXEC_ROOT__/generated", env={"VALUE": "action"})

            project = assemble([crate], {"__EXEC_ROOT__/": root, "__WORKSPACE__/": root}, Path("/tools"))

        library = project["crates"][0]
        self.assertIn("generated_api", library["cfg"])
        self.assertIn('feature="generated"', library["cfg"])
        self.assertEqual(library["env"]["VALUE"], "second=with-equals")
        self.assertEqual(library["env"]["PATH"], str(root / "input"))
        self.assertEqual(library["env"]["OUT_DIR"], str(root / "generated"))
        self.assertEqual(library["env"]["GENERATED"], str(root / "generated/api.rs"))

    def test_compiler_files_preserve_newline_and_backslash_escaping(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "env"
            path.write_text("TEXT=first\\\nsecond\nTRAIL=slash\\\\\n\n")
            self.assertEqual(compiler_file_lines(path), ["TEXT=first\nsecond", "TRAIL=slash\\"])

    def test_compiler_files_preserve_non_newline_control_characters(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "env"
            path.write_bytes(b"TEXT=first\x0bsecond\r\nFINAL=trailing\r")
            self.assertEqual(compiler_file_lines(path), ["TEXT=first\x0bsecond", "FINAL=trailing\r"])

    def test_unavailable_build_script_metadata_fails_export(self):
        with self.assertRaises(FileNotFoundError):
            self.assemble([spec("lib", aos_build_script_flags="__EXEC_ROOT__/missing")])

    def test_completed_build_ignores_unreachable_previous_specs(self):
        events = [
            {"id": {"namedSet": {"id": "current"}}, "namedSetOfFiles": {
                "files": [{"name": "lib.rust_analyzer_crate_spec.json", "uri": "file:///current.json"}]}},
            {"id": {"namedSet": {"id": "previous"}}, "namedSetOfFiles": {
                "files": [{"name": "old.rust_analyzer_crate_spec.json", "uri": "file:///stale.json"}]}},
            {"id": {"targetCompleted": {}}, "completed": {"success": True, "outputGroup": [
                {"name": "rust_analyzer_crate_spec", "fileSets": [{"id": "current"}]}]}},
            {"id": {"buildFinished": {}}, "finished": {"exitCode": {"name": "SUCCESS"}}},
        ]
        self.assertEqual(current_specs(events), [Path("/current.json")])

    def test_ambiguous_feature_variants_fail(self):
        with self.assertRaisesRegex(ValueError, "ambiguous configured Rust variant"):
            self.assemble([spec("lib"), spec("lib", cfg=['feature="different"'])])

    def test_missing_transitive_dependency_fails(self):
        with self.assertRaisesRegex(ValueError, "missing configured Rust dependency"):
            self.assemble([spec("lib", deps=["missing"])])

    def test_incomplete_build_cannot_export_previous_outputs(self):
        with self.assertRaisesRegex(ValueError, "successful completed build"):
            current_specs([])


if __name__ == "__main__":
    unittest.main()

"""Checks editor cfg correction without replacing configured compiler metadata."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


path = Path(__file__).resolve().parents[1] / "metadata/editor_cfg.py"
specification = importlib.util.spec_from_file_location("editor_cfg", path)
adapter = importlib.util.module_from_spec(specification)
specification.loader.exec_module(adapter)


class EditorCfgTests(unittest.TestCase):
    def project(self):
        return {
            "sysroot": "/declared/toolchain",
            "crates": [
                {"root_module": "/workspace/crates/guest/src/lib.rs",
                 "cfg": ["test", "debug_assertions", 'feature="selected"', 'target_feature="stale"'],
                 "deps": [{"crate": 1, "name": "renamed_macro"}]},
                {"root_module": "/execution/external/macro/src/lib.rs",
                 "cfg": ["debug_assertions", 'feature="derive"'],
                 "deps": [], "is_proc_macro": True,
                 "proc_macro_dylib_path": "/execution/declared/macro.so"},
            ],
        }

    def test_static_target_cfgs_preserve_features_dependencies_and_macro_artifacts(self):
        original = self.project()
        cfg = ['target_arch="x86_64"', 'target_feature="crt-static"']
        result = adapter.apply_cfg(original, cfg, "/workspace")

        self.assertNotIn("debug_assertions", result["crates"][0]["cfg"])
        self.assertIn('target_feature="crt-static"', result["crates"][0]["cfg"])
        self.assertNotIn('target_feature="stale"', result["crates"][0]["cfg"])
        self.assertIn("rust_analyzer", result["crates"][0]["cfg"])
        self.assertNotIn("rust_analyzer", result["crates"][1]["cfg"])
        self.assertIn("debug_assertions", original["crates"][0]["cfg"])

        for before, after in zip(original["crates"], result["crates"]):
            self.assertEqual({key: value for key, value in before.items() if key != "cfg"},
                             {key: value for key, value in after.items() if key != "cfg"})
            self.assertEqual({cfg for cfg in before["cfg"] if cfg.startswith("feature=")},
                             {cfg for cfg in after["cfg"] if cfg.startswith("feature=")})

    def test_explicit_native_assertions_remain_enabled(self):
        result = adapter.apply_cfg(self.project(), ["debug_assertions", 'target_arch="x86_64"', 'feature="global"'], "/workspace")

        self.assertTrue(all("debug_assertions" in crate["cfg"] for crate in result["crates"]))
        self.assertIn('feature="selected"', result["crates"][0]["cfg"])
        self.assertTrue(all('feature="global"' in crate["cfg"] for crate in result["crates"]))

    def test_compiler_query_preserves_native_flag_order(self):
        flags = ["-Ctarget-feature=+crt-static", "-Cdebug-assertions=yes"]
        with patch.object(adapter.subprocess, "run", return_value=SimpleNamespace(
            stdout='debug_assertions\ntarget_arch="x86_64"\n',
        )) as run:
            query = adapter.compiler_cfg("/declared/rustc", "x86_64-unknown-linux-gnu", flags)

        self.assertEqual(query["arguments"], ["/declared/rustc", *flags, "-O", "--target",
                                              "x86_64-unknown-linux-gnu", "--print", "cfg"])
        run.assert_called_once_with(query["arguments"], check=True, capture_output=True, text=True)

    def test_invalid_compiler_responses_and_undeclared_compilers_fail_closed(self):
        for output in ["", "warning: unexpected output\n", 'target_arch="x86_64"\ntarget_arch="x86_64"\n', "unix\n"]:
            with self.subTest(output=output), patch.object(adapter.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
                with self.assertRaises(ValueError):
                    adapter.compiler_cfg("/declared/rustc", "x86_64-unknown-linux-gnu", [])

        with self.assertRaises(ValueError):
            adapter.compiler_cfg("rustc", "x86_64-unknown-linux-gnu", [])

    def test_export_failure_preserves_the_previous_project(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "rust-project.json"
            output.write_text(json.dumps(self.project()))
            original = output.read_bytes()
            arguments = ["exporter", "--workspace", "/workspace", "--output", str(output)]

            with patch.object(sys, "argv", arguments), patch.object(adapter, "compiler_cfg", return_value={"cfg": []}):
                with patch.object(adapter.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["exporter"])):
                    with self.assertRaises(subprocess.CalledProcessError):
                        adapter.main("/declared/exporter.py", "/declared/rustc", "x86_64-unknown-linux-gnu", [])

            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(sorted(path.name for path in Path(scratch).iterdir()), ["rust-project.json"])


if __name__ == "__main__":
    unittest.main()

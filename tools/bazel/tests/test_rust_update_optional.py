"""Checks optional dependency specialization against reviewed source manifests."""

import ast
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_rust_update import updater


class OptionalDependencyUpdateTests(unittest.TestCase):
    def feature_graph(self):
        policy = {
            "feature_variants": {
                "root": {
                    "version": "1",
                    "resolved_features": ["runtime"],
                    "features": ["runtime"],
                    "exec_features": [],
                    "prune_optional_dependencies": True,
                },
            },
        }
        context = {
            "crates": {
                "root": {
                    "name": "root",
                    "version": "1",
                    "library_target_name": "root",
                    "common_attrs": {
                        "crate_features": {"common": ["runtime"], "selects": {}},
                        "deps": {
                            "common": [
                                {"id": "dependency", "target": "dependency", "alias": "renamed"},
                                {"id": "root", "target": "build_script_build"},
                            ],
                            "selects": {},
                        },
                    },
                },
                "dependency": {
                    "name": "dependency",
                    "version": "1",
                    "library_target_name": "dependency",
                },
            },
        }
        manifests = {
            ("root", "1"): {
                "dependencies": {"renamed": {"package": "dependency", "version": "1", "optional": True}},
                "build-dependencies": {"dependency": "1"},
                "features": {"runtime": ["dep:renamed"]},
            },
        }
        builds = {
            ("root", "1"): '''rust_library(
    name = "root",
    crate_features = ["runtime"],
    deps = ["@sdk__dependency-1//:dependency", "@sdk__root-1//:build_script_build"],
    aliases = {"@sdk__dependency-1//:dependency": "renamed"},
)
cargo_build_script(
    name = "_bs",
    crate_features = ["runtime"],
    deps = ["@sdk__dependency-1//:dependency"],
)
alias(name = "build_script_build", actual = ":_bs")
''',
        }
        return policy, context, builds, manifests

    def test_execution_library_prunes_renamed_optional_edge_but_preserves_build_dependencies(self):
        policy, context, builds, manifests = self.feature_graph()

        result = updater.specialize_feature_graph(policy, context, builds, "sdk", manifests)["root", "1"]
        rules = {}
        for statement in ast.parse(result).body:
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id not in {"rust_library", "cargo_build_script"}:
                continue
            attributes = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
            rules[attributes["name"]] = attributes

        label = "@sdk__dependency-1//:dependency"
        self.assertIn(label, rules["root__aos_target"]["deps"])
        self.assertEqual(rules["root__aos_target"]["aliases"], {label: "renamed"})
        self.assertNotIn(label, rules["root__aos_exec"]["deps"])
        self.assertEqual(rules["root__aos_exec"]["aliases"], {})
        self.assertIn(label, rules["_bs__aos_target"]["deps"])
        self.assertIn(label, rules["_bs__aos_exec"]["deps"])
        self.assertEqual(rules["_bs__aos_target"]["crate_features"], ["runtime"])
        self.assertEqual(rules["_bs__aos_exec"]["crate_features"], [])

    def test_missing_source_manifest_and_nonboolean_policy_fail_closed(self):
        policy, context, builds, manifests = self.feature_graph()
        for provided in [None, {}]:
            with self.subTest(manifests=provided), self.assertRaisesRegex(ValueError, "authenticated source manifest"):
                updater.specialize_feature_graph(policy, context, dict(builds), "sdk", provided)

        policy["feature_variants"]["root"]["prune_optional_dependencies"] = "yes"
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            updater.specialize_feature_graph(policy, context, dict(builds), "sdk", manifests)

    def test_named_variant_prunes_base_before_redirecting_consumers(self):
        policy, context, builds, manifests = self.feature_graph()
        settings = policy["feature_variants"]["root"]
        settings.pop("exec_features")
        settings["features"] = []
        settings["variants"] = {
            "with_runtime": {"features": ["runtime"], "dependents": {"consumer": "1"}},
        }
        builds["consumer", "1"] = 'rust_library(name = "consumer", deps = ["@sdk__root-1//:root"])\n'

        result = updater.specialize_feature_graph(policy, context, builds, "sdk", manifests)
        base, variant = result["root", "1"].split("# Reviewed Cargo feature unit: with_runtime")

        self.assertIn('deps = ["@sdk__root-1//:build_script_build"]', base)
        self.assertIn('"@sdk__dependency-1//:dependency"', variant)
        self.assertIn('"@sdk__root-1//:root__aos_with_runtime"', result["consumer", "1"])

    def test_stale_installed_updater_or_helper_is_rejected_before_resolution(self):
        for changed in ["update_rust.py", "optional_dependencies.py"]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                metadata = root / "tools/bazel/metadata"
                metadata.mkdir(parents=True)
                for filename in ["update_rust.py", "optional_dependencies.py"]:
                    data = Path(updater.__file__).with_name(filename).read_bytes()
                    (metadata / filename).write_bytes(data)
                changed_path = metadata / changed
                changed_path.write_bytes(changed_path.read_bytes() + b"\n# Changed input.\n")
                specification = root / "specification.json"
                specification.write_text(json.dumps({"schema_version": 1, "family": "example", "contracts": {}}))
                tools = root / "tools.json"
                tools.write_text("{}\n")
                arguments = [
                    "update_rust.py", "--specifications", str(specification),
                    "--tool-config", str(tools), "--root", str(root),
                    "--output", str(root / "output"),
                ]
                errors = io.StringIO()

                with patch.object(sys, "argv", arguments), patch.object(updater, "resolve") as resolve:
                    with redirect_stderr(errors), self.assertRaises(SystemExit) as rejected:
                        updater.main()

                self.assertEqual(rejected.exception.code, 2)
                self.assertIn("installed Rust updater is stale; rebuild its package: " + changed, errors.getvalue())
                resolve.assert_not_called()
                self.assertFalse((root / "output").exists())

    def test_inline_rule_without_trailing_comma_remains_valid_after_feature_rewrite(self):
        rendered = 'rust_library(name = "root", crate_features = ["runtime"])\n'

        result = updater.rewrite_features(rendered, ["runtime"], [], "__aos_exec", "sdk")

        call = ast.parse(result).body[0].value
        attributes = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
        self.assertEqual(attributes["crate_name"], "root")
        self.assertEqual(attributes["crate_features"], [])


if __name__ == "__main__":
    unittest.main()

"""Checks configured license identities, bridge traversal, and closed ownership."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
from export_license_closures import export_closure, pinned_sources


ROOT = "//crates/plugin:plugin"
REPOSITORY = "aos_fixture__upstream-1.2.3"
EXTERNAL = "@@+aos_tools_repository+" + REPOSITORY + "//:upstream"


def compilation(label, kind="rust_library", root=None, version="0.1.0", **overrides):
    external = label.startswith("@@")
    if root is None:
        directory = label.removeprefix("@@").partition("//")[0] if external else "crates/plugin"
        root = ("../" if external else "") + directory + "/src/lib.rs"
    return {"schema_version": 1, "label": label, "kind": kind, "external": external,
            "crate_root": root, "version": version, "dependencies": [], **overrides}


class LicenseClosureTests(unittest.TestCase):
    def setUp(self):
        self.architecture = {
            "schema_version": 1,
            "packages": [{"name": "plugin", "directory": "crates/plugin", "version": "0.1.0", "license": "GPL-2.0-only"}],
            "compilation_targets": {ROOT: {"package": "plugin", "test_only": False, "kind": "rust_shared_library", "crate_roots": ["src/lib.rs"]}},
        }
        self.inventory = {"schema_version": 1, "targets": [ROOT], "configured_targets": [
            compilation(ROOT, "rust_shared_library"), compilation(EXTERNAL, version="1.2.3"),
        ]}
        self.sources = {REPOSITORY: {"name": "upstream-original", "version": "1.2.3", "license": "MIT OR Apache-2.0", "sha256": "a" * 64}}

    def export(self):
        return export_closure(self.inventory, ROOT, self.architecture, self.sources)

    def test_uses_pinned_package_names_versions_licenses_and_archive_hashes(self):
        result = self.export()
        external = next(package for package in result["packages"] if package["source"] == "sdk")

        self.assertEqual(external["name"], "upstream-original")
        self.assertEqual(external["license"], "MIT OR Apache-2.0")
        self.assertEqual(external["sha256"], "a" * 64)
        self.assertEqual(external["compilation_targets"], [EXTERNAL])
        self.assertEqual(result["root_package"], "plugin")

    def test_build_dependencies_survive_non_rust_bridge_rules(self):
        self.inventory["configured_targets"] += [
            {"schema_version": 1, "label": "//crates/plugin:build", "kind": "cargo_build_script", "crate_root": ""},
            compilation(EXTERNAL.replace(":upstream", ":_bs_"), "rust_binary", version="0.0.0",
                        root="../+aos_tools_repository+" + REPOSITORY + "/build.rs"),
        ]
        # There is deliberately no direct Rust-to-Rust edge. The aspect's
        # transitive report membership crosses the non-Rust bridge.
        result = self.export()
        external = next(package for package in result["packages"] if package["source"] == "sdk")

        self.assertEqual(len(external["compilation_targets"]), 2)
        self.assertEqual(external["version"], "1.2.3")

    def test_procedural_macro_and_execution_profile_copies_are_included(self):
        macro = compilation(EXTERNAL.replace(":upstream", ":derive"), "rust_proc_macro", version="1.2.3")
        self.inventory["configured_targets"] += [macro, copy.deepcopy(macro)]

        external = next(package for package in self.export()["packages"] if package["source"] == "sdk")

        self.assertEqual(external["compilation_targets"], sorted([EXTERNAL, macro["label"]]))

    def test_shared_library_without_crate_provider_requires_its_declared_configured_source(self):
        root = self.inventory["configured_targets"][0]
        root.update(crate_root="", sources=["crates/plugin/src/lib.rs"])

        self.assertEqual(self.export()["root_package"], "plugin")

        root["sources"] = ["crates/plugin/src/other.rs"]
        with self.assertRaisesRegex(ValueError, "configured sources"):
            self.export()

    def test_single_production_root_is_required(self):
        for targets in [[], [ROOT, "//crates/other:lib"]]:
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                self.inventory["targets"] = targets
                self.export()

    def test_missing_and_test_only_roots_fail_closed(self):
        self.inventory["configured_targets"].pop(0)
        with self.assertRaisesRegex(ValueError, "omitted its production"):
            self.export()
        self.architecture["compilation_targets"][ROOT]["test_only"] = True
        with self.assertRaisesRegex(ValueError, "production compilation"):
            self.export()

    def test_wrong_root_owner_and_artifact_kind_are_rejected(self):
        for field, value in [("package", "wrong"), ("kind", "rust_binary")]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "source declaration"):
                architecture = copy.deepcopy(self.architecture)
                architecture["compilation_targets"][ROOT][field] = value
                export_closure(self.inventory, ROOT, architecture, self.sources)

    def test_unknown_external_packages_and_rule_tools_fail_closed(self):
        for label in ["@@unregistered//:lib", "@@rules_rust+//new:helper", EXTERNAL.replace(REPOSITORY, "unknown")]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.inventory["configured_targets"][1]["label"] = label
                self.export()

    def test_only_exact_pinned_rule_implementation_tools_are_excluded(self):
        tool = compilation("@@rules_rust+//util/process_wrapper:process_wrapper", "rust_binary_without_process_wrapper")
        self.inventory["configured_targets"].append(tool)

        result = self.export()

        self.assertEqual(list(result["excluded_rule_tools"]), [tool["label"]])
        self.assertEqual(len(result["packages"]), 2)
        tool["kind"] = "rust_library"
        with self.assertRaisesRegex(ValueError, "changed compilation kind"):
            self.export()

    def test_missing_source_roots_and_unknown_compilation_kinds_fail_closed(self):
        for changes in [{"crate_root": ""}, {"kind": "rust_test"}, {"kind": "foreign_rust_compiler"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                inventory = copy.deepcopy(self.inventory)
                inventory["configured_targets"][1].update(changes)
                export_closure(inventory, ROOT, self.architecture, self.sources)

    def test_source_root_escape_and_version_drift_fail_closed(self):
        for changes in [{"crate_root": "../elsewhere/src/lib.rs"},
                        {"crate_root": "../+aos_tools_repository+" + REPOSITORY + "/../escape.rs"},
                        {"version": "9.9.9"}, {"version": "0.0.0"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                inventory = copy.deepcopy(self.inventory)
                inventory["configured_targets"][1].update(changes)
                export_closure(inventory, ROOT, self.architecture, self.sources)

    def test_first_party_source_ownership_and_version_must_match(self):
        for changes in [{"label": "//crates/orphan:lib"}, {"label": "//crates/plugin:undeclared"},
                        {"crate_root": "crates/other/lib.rs"}, {"crate_root": "crates/plugin/src/other.rs"},
                        {"version": "9.9.9"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                inventory = copy.deepcopy(self.inventory)
                inventory["configured_targets"][0].update(changes)
                export_closure(inventory, ROOT, self.architecture, self.sources)

    def test_source_manifests_reject_conflicts_and_incomplete_license_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["first", "second"]:
                (directory / name).mkdir()
                (directory / name / "sources.json").write_text(json.dumps({"schema_version": 1, "sources": self.sources}))
            sources, manifests = pinned_sources(directory)
            self.assertEqual(sources, self.sources)
            self.assertEqual(len(manifests), 2)

            for changes in [{"license": "GPL-3.0-only"}, {"license": ""}, {"sha256": "bad"}]:
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    source = {**self.sources[REPOSITORY], **changes}
                    (directory / "second/sources.json").write_text(json.dumps({"schema_version": 1, "sources": {REPOSITORY: source}}))
                    pinned_sources(directory)


if __name__ == "__main__":
    unittest.main()

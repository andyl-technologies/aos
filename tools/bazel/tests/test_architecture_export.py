"""Checks that architecture metadata preserves every production selector branch."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
from export_architecture import attribute_values, export, repository_packages


def attribute(name, kind, value):
    field = {"STRING": "stringValue", "LABEL": "stringValue", "STRING_LIST": "stringListValue",
             "LABEL_LIST": "stringListValue", "BOOLEAN": "booleanValue"}[kind]
    return {"name": name, "type": kind, field: value}


def record(label, kind, *attrs):
    attrs = list(attrs)
    if kind in {"rust_library", "rust_binary", "rust_proc_macro", "rust_shared_library", "rust_static_library"}:
        defaults = [attribute("crate_root", "LABEL", label.partition(":")[0] + ":src/lib.rs"),
                    attribute("crate_name", "STRING", label.partition(":")[2]),
                    attribute("crate_features", "STRING_LIST", []),
                    attribute("tags", "STRING_LIST", [])]
        attrs.extend(row for row in defaults if row["name"] not in {item["name"] for item in attrs})
    return {"type": "RULE", "rule": {"name": label, "ruleClass": kind, "attribute": attrs}}


def source(package, **overrides):
    identity = {"name": package, "version": "0.1.0", "edition": "2024",
                "license": "MIT OR Apache-2.0", "license_domain": "apache-host"}
    identity.update(overrides)
    return record("//crates/" + package + ":source", "_source_package",
                  attribute("identity", "STRING", json.dumps(identity)))


def compilation(name, target="lib", deps=(), testonly=False, **extra):
    return record("//crates/" + name + ":" + target, "rust_library",
                  attribute("testonly", "BOOLEAN", testonly),
                  attribute("deps", "LABEL_LIST", list(deps)),
                  *(attribute(key, "LABEL_LIST", value) for key, value in extra.items()))


def selected(name, kind, *branches):
    field = "stringValue" if kind == "LABEL" else "stringListValue"
    return {"name": name, "type": "SELECTOR_LIST", "selectorList": {
        "type": kind, "elements": [{"entries": [
            {"label": condition, field: value} for condition, value in branch.items()
        ]} for branch in branches],
    }}


class ArchitectureExportTests(unittest.TestCase):
    def packages(self, records, repositories=None):
        result = export(records, repositories or {})
        return {package["name"]: package for package in result["packages"]}

    def test_selector_union_retains_concatenated_branches_without_condition_edges(self):
        deps = selected("deps", "LABEL_LIST",
                        {"//conditions:default": ["//crates/b:lib"], "//platform:other": ["//crates/c:lib"]},
                        {"//features:optional": ["//crates/d:lib"], "//conditions:default": []})
        records = [source(name) for name in "abcd"] + [compilation(name) for name in "bcd"]
        records.append(record("//crates/a:lib", "rust_library", attribute("testonly", "BOOLEAN", False), deps))

        self.assertEqual(self.packages(records)["a"]["production_dependencies"], ["b", "c", "d"])

    def test_only_production_rust_dependency_attributes_contribute_edges(self):
        records = [source("app"), source("macro"), source("build"), source("dev")]
        records += [compilation("macro"), compilation("build"), compilation("dev"), compilation("app", deps=["//crates/app:build_program"],
                    proc_macro_deps=["//crates/macro:lib"], data=["//missing:data"], tools=["//missing:tool"]),
                    compilation("app", "test", ["//crates/dev:lib"], testonly=True)]
        build_program = compilation("app", "build_program", ["//crates/build:lib"])
        build_program["rule"]["ruleClass"] = "rust_binary"
        records.append(build_program)

        self.assertEqual(self.packages(records)["app"]["production_dependencies"], ["build", "macro"])

    def test_dependency_view_retains_tests_build_scripts_and_unit_crate_edges(self):
        records = [source(name) for name in ["app", "dev", "build", "macro"]]
        records += [compilation(name) for name in ["app", "dev", "build", "macro"]]
        records += [
            record("//crates/app:integration", "rust_test", attribute("testonly", "BOOLEAN", True),
                   attribute("deps", "LABEL_LIST", ["//crates/dev:lib"]),
                   attribute("proc_macro_deps", "LABEL_LIST", ["//crates/macro:lib"])),
            record("//crates/app:unit", "rust_test", attribute("testonly", "BOOLEAN", True),
                   attribute("crate", "LABEL", "//crates/app:lib")),
            record("//crates/app:build_script", "cargo_build_script", attribute("testonly", "BOOLEAN", False),
                   attribute("deps", "LABEL_LIST", ["//crates/build:lib"])),
        ]
        result = export(records, {})
        targets = result["dependency_targets"]
        self.assertEqual(targets["//crates/app:integration"], {
            "package": "app", "kind": "rust_test", "test_only": True,
            "dependencies": [
                {"attribute": "deps", "label": "//crates/dev:lib", "packages": ["dev"]},
                {"attribute": "proc_macro_deps", "label": "//crates/macro:lib", "packages": ["macro"]},
            ],
        })
        self.assertEqual(targets["//crates/app:unit"]["dependencies"], [
            {"attribute": "crate", "label": "//crates/app:lib", "packages": []},
        ])
        self.assertEqual(targets["//crates/app:build_script"]["dependencies"][0]["packages"], ["build"])
        app = next(package for package in result["packages"] if package["name"] == "app")
        self.assertEqual(app["production_dependencies"], [])
        self.assertEqual(app["production_targets"], ["//crates/app:lib"])
        self.assertNotIn("//crates/app:integration", result["compilation_targets"])

    def test_test_only_dependency_aliases_union_every_profile_and_use_sdk_names(self):
        records = [source("app"), compilation("app"), record(
            "//crates/app:test", "rust_test", attribute("testonly", "BOOLEAN", True),
            selected("deps", "LABEL_LIST", {"//conditions:default": ["//third_party/rust:renamed"],
                                            "//platform:other": ["@second//:lib"]}),
            attribute("data", "LABEL_LIST", ["//missing:runfile"])),
            record("//third_party/rust:renamed", "alias", selected("actual", "LABEL", {
                "//conditions:default": "@first//:lib", "//profiles:other": "@second//:lib"})),
        ]
        result = export(records, {"first": "ratchet-original", "second": "aos-nix-original"})
        dependencies = result["dependency_targets"]["//crates/app:test"]["dependencies"]
        self.assertEqual({name for edge in dependencies for name in edge["packages"]},
                         {"ratchet-original", "aos-nix-original"})
        self.assertEqual(result["packages"][0]["production_dependencies"], [])

    def test_native_test_edges_do_not_pollute_production_native_membership(self):
        records = [source("app"), compilation("app", deps=["@aos_native//:production"]),
                   record("//crates/app:test", "rust_test", attribute("testonly", "BOOLEAN", True),
                          attribute("deps", "LABEL_LIST", ["@aos_native//:test", "//native/test:fixture"]))]
        result = export(records, {})
        self.assertEqual(result["native_dependencies"], ["@aos_native//:production"])
        self.assertEqual([edge["label"] for edge in result["dependency_targets"]["//crates/app:test"]["dependencies"]],
                         ["//native/test:fixture", "@aos_native//:test"])

    def test_unresolved_test_and_build_script_dependencies_fail_closed(self):
        for kind in ["rust_test", "cargo_build_script"]:
            rule = record("//crates/app:helper", kind, attribute("testonly", "BOOLEAN", True),
                          attribute("deps", "LABEL_LIST", ["//missing:dependency"]))
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unmodeled architecture dependency"):
                export([source("app"), compilation("app"), rule], {})

    def test_test_binaries_do_not_become_linkable_production_dependencies(self):
        records = [source("app"), source("helper"),
                   compilation("app", deps=["//crates/helper:test"]), compilation("helper"),
                   record("//crates/helper:test", "rust_test", attribute("testonly", "BOOLEAN", True))]
        with self.assertRaisesRegex(ValueError, "unmodeled architecture dependency"):
            export(records, {})

    def test_documentation_and_lint_dependencies_include_test_artifacts_without_changing_linkability(self):
        records = [source("app"), source("helper"), compilation("app"), compilation("helper"),
                   record("//crates/helper:test", "rust_test", attribute("testonly", "BOOLEAN", True)),
                   record("//crates/app:renamed_test", "alias", attribute("actual", "LABEL", "//crates/helper:test"))]
        for kind in ["rust_doc", "rust_doc_test", "rust_clippy"]:
            records.append(record("//crates/app:" + kind, kind, attribute("testonly", "BOOLEAN", True),
                                  attribute("crate", "LABEL", "//crates/app:lib"),
                                  attribute("deps", "LABEL_LIST", ["//crates/app:renamed_test"])))
        result = export(records, {})
        for kind in ["rust_doc", "rust_doc_test", "rust_clippy"]:
            self.assertEqual(result["dependency_targets"]["//crates/app:" + kind]["dependencies"][0]["packages"], ["helper"])
        app = next(package for package in result["packages"] if package["name"] == "app")
        self.assertEqual(app["production_dependencies"], [])

        # The permissive traversal for lint/test inputs must not change the
        # production alias resolver or share its cached results.
        records.append(compilation("app", "invalid", deps=["//crates/app:renamed_test"]))
        with self.assertRaisesRegex(ValueError, "unmodeled architecture dependency"):
            export(records, {})

    def test_dependency_targets_require_ownership_and_nonconfigurable_test_selection(self):
        for rule in [
            record("//crates/orphan:test", "rust_test", attribute("testonly", "BOOLEAN", True)),
            record("//crates/app:test", "rust_test", selected("testonly", "LABEL", {"//conditions:default": "yes"})),
        ]:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                export([source("app"), compilation("app"), rule], {})

    def test_metadata_only_packages_remain_unmodeled_instead_of_independent(self):
        packages = self.packages([source("app"), source("pending"), compilation("app", deps=["//crates/pending:lib"]),
                                  compilation("pending", testonly=True)])
        self.assertIsNone(packages["pending"]["production_dependencies"])
        self.assertEqual(packages["pending"]["production_targets"], [])
        self.assertEqual(packages["app"]["production_dependencies"], ["pending"])

    def test_aliases_follow_all_profiles_and_authoritative_upstream_names(self):
        marker = "//tools/bazel/rules:device_profile_required"
        records = [source("app"), compilation("app", deps=["//third_party/rust:renamed"]),
                   record(marker, "device_profile_required"),
                   record("//third_party/rust:renamed", "alias", selected("actual", "LABEL", {
                       "//profiles:first": "@sdk_first//:lib", "//profiles:second": "@sdk_second//:lib",
                       "//conditions:default": marker}))]
        result = export(records, {"sdk_first": "upstream-original", "sdk_second": "upstream-second"})

        self.assertEqual(result["packages"][0]["production_dependencies"], ["upstream-original", "upstream-second"])
        self.assertEqual(result["unavailable_profile_targets"], {marker: "device_profile_required"})

    def test_first_party_alias_does_not_hide_a_different_package(self):
        records = [source("app"), source("other"), compilation("app", deps=["//crates/app:redirect"]),
                   compilation("other"), record("//crates/app:redirect", "alias",
                                              attribute("actual", "LABEL", "//crates/other:lib"))]
        self.assertEqual(self.packages(records)["app"]["production_dependencies"], ["other"])

    def test_unknown_labels_alias_cycles_and_marker_only_aliases_fail_closed(self):
        base = [source("app"), compilation("app", deps=["//third_party/rust:dependency"])]
        variants = [[], [record("//third_party/rust:dependency", "alias", attribute("actual", "LABEL", "//crates/app:missing"))],
                    [record("//third_party/rust:dependency", "alias", attribute("actual", "LABEL", "//third_party/rust:dependency"))],
                    [record("//tools/bazel/rules:device_profile_required", "device_profile_required"),
                     record("//third_party/rust:dependency", "alias", attribute("actual", "LABEL", "//tools/bazel/rules:device_profile_required"))]]
        for additional in variants:
            with self.subTest(additional=additional), self.assertRaises(ValueError):
                export(base + additional, {})

    def test_missing_ownership_duplicate_rules_and_invalid_identity_fail_closed(self):
        base = [source("app"), compilation("app")]
        variants = [[compilation("orphan")], [source("app")], [source("other", name="app")],
                    [source("invalid", license="")], [record("//foreign:rule", "unknown_rule")]]
        for additional in variants:
            with self.subTest(additional=additional), self.assertRaises(ValueError):
                export(base + additional, {})

    def test_duplicate_attributes_and_wrong_selector_types_fail_closed(self):
        original = compilation("app")
        for additional in [attribute("deps", "LABEL_LIST", []), selected("deps", "LABEL", {"//conditions:default": "//x:y"})]:
            malformed = copy.deepcopy(original)
            if additional["type"] == "SELECTOR_LIST":
                malformed["rule"]["attribute"] = [row for row in malformed["rule"]["attribute"] if row["name"] != "deps"]
            malformed["rule"]["attribute"].append(additional)
            with self.subTest(additional=additional), self.assertRaises(ValueError):
                export([source("app"), malformed], {})

    def test_native_edges_are_retained_separately(self):
        result = export([source("app"), compilation("app", deps=["@aos_native//:sqlite", "//native/ffi:helper"])], {})
        self.assertEqual(result["packages"][0]["production_dependencies"], [])
        self.assertEqual(result["native_dependencies"], ["//native/ffi:helper", "@aos_native//:sqlite"])

    def test_sdk_names_are_pinned_and_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["first", "second"]:
                (directory / name).mkdir()
                (directory / name / "sources.json").write_text(json.dumps({
                    "schema_version": 1, "sources": {"sdk_original": {"name": "upstream-original"}},
                }))
            names, hashes = repository_packages(directory)
            self.assertEqual(names, {"sdk_original": "upstream-original"})
            self.assertEqual(set(hashes), {"first/sources.json", "second/sources.json"})

            (directory / "second/sources.json").write_text(json.dumps({
                "schema_version": 1, "sources": {"sdk_original": {"name": "conflicting"}},
            }))
            with self.assertRaisesRegex(ValueError, "conflicting"):
                repository_packages(directory)

    def test_artifacts_retain_test_only_variants_roots_features_and_tags(self):
        records = [source("app"), compilation("app"), record(
            "//crates/app:oracle", "rust_binary", attribute("testonly", "BOOLEAN", True),
            attribute("crate_root", "LABEL", "//crates/app:src/bin/oracle.rs"),
            attribute("crate_name", "STRING", "oracle"),
            attribute("crate_features", "STRING_LIST", ["opt-in"]),
            attribute("tags", "STRING_LIST", ["manual"]))]
        result = export(records, {})
        oracle = result["compilation_targets"]["//crates/app:oracle"]

        self.assertEqual(oracle, {"package": "app", "kind": "rust_binary", "crate_name": "oracle",
                                 "crate_roots": ["src/bin/oracle.rs"], "features": ["opt-in"],
                                 "tags": ["manual"], "test_only": True})
        self.assertEqual(result["packages"][0]["production_targets"], ["//crates/app:lib"])

    def test_artifact_roots_and_features_preserve_selector_union(self):
        records = [source("app"), record(
            "//crates/app:lib", "rust_library", attribute("testonly", "BOOLEAN", False),
            selected("crate_root", "LABEL", {"//conditions:default": "//crates/app:src/lib.rs",
                                              "//platform:other": "//crates/app:src/other.rs"}),
            selected("crate_features", "STRING_LIST", {"//conditions:default": ["default"],
                                                       "//platform:other": ["other"]}))]
        artifact = export(records, {})["compilation_targets"]["//crates/app:lib"]
        self.assertEqual(artifact["crate_roots"], ["src/lib.rs", "src/other.rs"])
        self.assertEqual(artifact["features"], ["default", "other"])

    def test_single_implicit_root_uses_source_identity_and_normalizes_default_crate_name(self):
        rule = record("//crates/app:some-command", "rust_binary",
                      attribute("testonly", "BOOLEAN", False), attribute("crate_name", "STRING", ""),
                      attribute("crate_root", "LABEL", ""),
                      attribute("srcs", "LABEL_LIST", ["//crates/app:examples/header.rs"]))
        # An absent optional label has no stringValue in streamed query output.
        next(row for row in rule["rule"]["attribute"] if row["name"] == "crate_root").pop("stringValue")
        artifact = export([source("app"), rule], {})["compilation_targets"]["//crates/app:some-command"]
        self.assertEqual(artifact["crate_roots"], ["examples/header.rs"])
        self.assertEqual(artifact["crate_name"], "some_command")

    def test_artifacts_reject_escaped_or_ambiguous_roots_and_configurable_test_selection(self):
        for root in ["//crates/other:src/lib.rs", "//crates/app:../escape.rs", "//crates/app:/absolute.rs"]:
            rule = record("//crates/app:lib", "rust_library", attribute("testonly", "BOOLEAN", False),
                          attribute("crate_root", "LABEL", root))
            with self.subTest(root=root), self.assertRaises(ValueError):
                export([source("app"), rule], {})
        for sources in [[], ["//crates/app:a.rs", "//crates/app:b.rs"]]:
            rule = compilation("app")
            attrs = rule["rule"]["attribute"]
            next(row for row in attrs if row["name"] == "crate_root").pop("stringValue")
            attrs.append(attribute("srcs", "LABEL_LIST", sources))
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                export([source("app"), rule], {})
        rule = compilation("app")
        next(row for row in rule["rule"]["attribute"] if row["name"] == "testonly")["type"] = "SELECTOR_LIST"
        with self.assertRaisesRegex(ValueError, "test-only selection"):
            export([source("app"), rule], {})

    def test_static_library_artifacts_cannot_disappear_from_the_audit(self):
        rule = compilation("app")
        rule["rule"]["ruleClass"] = "rust_static_library"
        result = export([source("app"), rule], {})
        self.assertEqual(result["compilation_targets"]["//crates/app:lib"]["kind"], "rust_static_library")


if __name__ == "__main__":
    unittest.main()

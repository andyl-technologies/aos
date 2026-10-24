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
    field = {"STRING": "stringValue", "LABEL": "stringValue",
             "LABEL_LIST": "stringListValue", "BOOLEAN": "booleanValue"}[kind]
    return {"name": name, "type": kind, field: value}


def record(label, kind, *attrs):
    return {"type": "RULE", "rule": {"name": label, "ruleClass": kind, "attribute": list(attrs)}}


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
        records = [source("app"), source("macro"), source("build")]
        records += [compilation("macro"), compilation("build"), compilation("app", deps=["//crates/app:build_program"],
                    proc_macro_deps=["//crates/macro:lib"], data=["//missing:data"], tools=["//missing:tool"]),
                    compilation("app", "test", ["//missing:dev"], testonly=True)]
        build_program = compilation("app", "build_program", ["//crates/build:lib"])
        build_program["rule"]["ruleClass"] = "rust_binary"
        records.append(build_program)

        self.assertEqual(self.packages(records)["app"]["production_dependencies"], ["build", "macro"])

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
                malformed["rule"]["attribute"].pop()
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


if __name__ == "__main__":
    unittest.main()

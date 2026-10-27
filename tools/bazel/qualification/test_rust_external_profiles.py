"""Rejects missing external units and compiler-role/profile mismatches."""

from copy import deepcopy
import unittest

from rust_external_profiles import add_unit, describe, match_units, native_target_roots, verify_external
from rust_profiles import require_matching_strip


class RustExternalProfileTests(unittest.TestCase):
    def arguments(self, role="target", strip=None):
        optimization = "0" if role == "execution" else "s"
        arguments = ["--crate-name=dependency", "--crate-type=lib", "--edition=2021",
                     '--cfg=feature="std"', "-Copt-level=" + optimization, "-Cdebuginfo=0",
                     "-Cdebug-assertions=yes", "-Coverflow-checks=yes"]
        if strip is not None:
            arguments.append("-Cstrip=" + strip)
        return arguments

    def unit(self, role="target", version="1.0.0", strip="debuginfo"):
        arguments = self.arguments(role, strip)
        key, options = describe(arguments, {"CARGO_PKG_NAME": "dependency", "CARGO_PKG_VERSION": version}, role)
        return key, {"label": "@@enrolled_dependency//:lib", "invocation": 3,
                     "arguments": arguments, "options": options}

    def fixture(self):
        source = "/build/source/crates/app/src/lib.rs"
        dependency = "/vendor/dependency/src/lib.rs"
        environment = {"CARGO_PKG_NAME": "dependency", "CARGO_PKG_VERSION": "1.0.0"}
        arguments = [*self.arguments(strip="debuginfo"), dependency,
                     "--out-dir=/build/target/debug/deps", "-Cextra-filename=-dep"]
        app = {"schema_version": 1, "directory": "/build/source/crates/app",
               "arguments": ["--crate-name=app", "--crate-type=lib", source,
                             "--out-dir=/build/target/debug/deps", "-Cextra-filename=-app",
                             "--extern=dependency=/build/target/debug/deps/libdependency-dep.rlib"]}
        native = {"schema_version": 1, "directory": "/vendor/dependency",
                  "arguments": arguments, "environment": environment}
        messages = [{"reason": "compiler-artifact", "target": {"src_path": path, "kind": ["lib"]}}
                    for path in [source, dependency]]
        action = {"target_label": "@@enrolled_dependency//:lib", "environment": environment,
                  "arguments": [argument.replace("--out-dir=/build/target/debug/deps", "--out-dir=bazel-out/target/bin")
                                for argument in arguments]}
        return [action], [{"mnemonic": "target", "isTool": False}], [app, native], messages

    def test_versions_and_roles_remain_distinct(self):
        ordinary, _ = self.unit()
        older, _ = self.unit(version="0.9.0")
        execution, _ = self.unit(role="execution")
        self.assertEqual(len({ordinary, older, execution}), 3)

    def test_library_artifact_extras_remain_explicit(self):
        arguments = [*self.arguments(), "--crate-type=cdylib,staticlib"]
        key, options = describe(arguments, {"CARGO_PKG_NAME": "dependency", "CARGO_PKG_VERSION": "1.0.0"}, "target")
        self.assertEqual(key[3], "rlib")
        self.assertEqual(options["declared_crate_types"], ["lib", "cdylib", "staticlib"])
        with self.assertRaisesRegex(ValueError, "crate-type combination"):
            describe([*arguments, "--crate-type=bin"], {"CARGO_PKG_NAME": "dependency", "CARGO_PKG_VERSION": "1.0.0"}, "target")

    def test_missing_identity_and_unknown_role_are_rejected(self):
        for environment, role in [({}, "target"), ({"CARGO_PKG_NAME": "dependency"}, "target"), ({}, "guessed")]:
            with self.subTest(environment=environment, role=role), self.assertRaises(ValueError):
                describe(self.arguments(), environment, role)

    def test_duplicate_external_executions_are_rejected(self):
        key, value = self.unit()
        index = {}
        add_unit(index, key, value)
        with self.assertRaisesRegex(ValueError, "duplicate external"):
            add_unit(index, key, value)

    def test_missing_extra_and_empty_inventories_fail(self):
        key, value = self.unit()
        older_key, older = self.unit(version="0.9.0")
        for actual, expected in [({}, {}), ({key: value}, {}), ({}, {key: value}),
                                 ({key: value, older_key: older}, {key: value})]:
            with self.subTest(actual=list(actual), expected=list(expected)), self.assertRaisesRegex(ValueError, "inventories differ"):
                match_units(actual, expected, True)

    def test_exact_units_and_selected_profiles_match(self):
        key, value = self.unit()
        rows = match_units({key: value}, {key: deepcopy(value)}, True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["native_invocation"], 3)
        self.assertEqual(rows[0]["role"], "target")

    def test_cfg_and_edition_mismatches_fail(self):
        key, value = self.unit()
        for field, replacement in [("cfg", ['feature="std"', "different_generated_cfg"]), ("edition", "2018")]:
            changed = deepcopy(value)
            changed["options"][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "cfg/edition differs"):
                match_units({key: changed}, {key: value}, True)

    def test_role_profile_cannot_be_inferred_from_wrong_optimization(self):
        key, value = self.unit(role="execution", strip="none")
        changed = deepcopy(value)
        changed["arguments"].append("-Copt-level=s")
        with self.assertRaisesRegex(ValueError, "optimization"):
            match_units({key: changed}, {key: value}, True)

    def test_stripping_mismatch_fails_only_when_enrolled(self):
        key, value = self.unit()
        changed = deepcopy(value)
        changed["arguments"].append("-Cstrip=none")
        with self.assertRaisesRegex(ValueError, "strip settings differ"):
            match_units({key: changed}, {key: value}, True)
        self.assertEqual(len(match_units({key: changed}, {key: value}, False)), 1)

    def test_strip_defaults_and_invalid_values(self):
        require_matching_strip({}, {"strip": "none"})
        require_matching_strip({"strip": "symbols"}, {"strip": "symbols"})
        for actual, expected in [({"strip": "unknown"}, {}), ({"strip": "none"}, {"strip": "debuginfo"})]:
            with self.subTest(actual=actual, expected=expected), self.assertRaises(ValueError):
                require_matching_strip(actual, expected)

    def test_declared_target_roots_exclude_generators_macros_and_probes(self):
        def invocation(source):
            return {"directory": "/build/source/crates/app", "arguments": [source]}

        def artifact(source, kind):
            return {"reason": "compiler-artifact", "target": {"src_path": source, "kind": [kind]}}

        sources = ["/build/source/crates/app/src/lib.rs", "/build/source/crates/app/build.rs",
                   "/build/source/crates/app/macro.rs", "/build/source/crates/app/probe.rs"]
        messages = [artifact(sources[0], "lib"), artifact(sources[1], "custom-build"),
                    artifact(sources[2], "proc-macro")]
        self.assertEqual(native_target_roots(list(map(invocation, sources)), messages), {sources[0]})

    def test_repository_enrollment_must_be_explicit(self):
        for prefix in ["", "//", "@@unbounded"]:
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, "canonical repository prefix"):
                verify_external([], [], [], [], prefix, True)

    def test_complete_artifact_graph_matches_without_profile_role_inference(self):
        report = verify_external(*self.fixture(), "@@enrolled_", True)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["units"]), 1)
        self.assertFalse(report["native_role_inference_uses_optimization"])
        self.assertEqual(len(report["native_role_graph"]["units"]), 2)

    def test_unenrolled_external_and_first_party_tools_fail(self):
        for label in ["@@unexpected_dependency//:lib", "//tools/new_generator:binary"]:
            actions, configurations, invocations, messages = self.fixture()
            actions[0]["target_label"] = label
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "unenrolled repository"):
                verify_external(actions, configurations, invocations, messages, "@@enrolled_", True)

    def test_pinned_build_system_helpers_require_execution_configuration(self):
        actions, configurations, invocations, messages = self.fixture()
        helper = deepcopy(actions[0])
        helper["target_label"] = "@@rules_rust++i+rules_rust_tinyjson//:tinyjson"
        with self.assertRaisesRegex(ValueError, "uses a target configuration"):
            verify_external([*actions, helper], configurations, invocations, messages, "@@enrolled_", True)

        helper["arguments"] = [argument.replace("bazel-out/target/", "bazel-out/execution/")
                               for argument in helper["arguments"]]
        configurations.append({"mnemonic": "execution", "isTool": True})
        result = verify_external([*actions, helper], configurations, invocations, messages, "@@enrolled_", True)
        self.assertEqual(len(result["units"]), 1)
        self.assertEqual(result["build_system_helpers"], [helper])
        with self.assertRaisesRegex(ValueError, "duplicated"):
            verify_external([*actions, helper, helper], configurations, invocations, messages, "@@enrolled_", True)


if __name__ == "__main__":
    unittest.main()

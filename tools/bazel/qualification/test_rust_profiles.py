"""Rejects profile, macro-version and configured-unit drift before qualification."""

import unittest

from rust_profiles import bind_native_defaults, bind_native_execution, generator_sources, macro_key, match_macros, native_macros, option, profile


class RustProfileTests(unittest.TestCase):
    def arguments(self, feature="std", edition="2021"):
        return ["rustc", "--crate-name=derive_impl", "--crate-type", "proc-macro",
                "--edition=" + edition, '--cfg=feature="' + feature + '"',
                "-Copt-level=0", "-Cdebuginfo=0", "-Cdebug-assertions=yes", "-Coverflow-checks=yes"]

    def native(self, version="2.0.0", feature="std"):
        return {"schema_version": 1, "arguments": self.arguments(feature=feature),
                "environment": {"CARGO_PKG_NAME": "derive-impl", "CARGO_PKG_VERSION": version}}

    def report(self, version="2.0.0"):
        return {"kind": "rust_proc_macro", "label": "@derive_" + version + "//:derive_impl",
                "tags": ["crate-name=derive-impl"], "version": version}

    def action(self, version="2.0.0", feature="std"):
        return {"target_label": self.report(version)["label"], "arguments": self.arguments(feature=feature)}

    def test_compiler_options_accept_both_forms_and_reject_ambiguity(self):
        self.assertEqual(option(["--crate-name", "name"], "--crate-name"), "name")
        self.assertEqual(option(["--crate-name=name"], "--crate-name"), "name")
        for arguments in [[], ["--crate-name"], ["--crate-name="], ["--crate-name", "--test"],
                          ["--crate-name=one", "--crate-name=two"]]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                option(arguments, "--crate-name")

    def test_native_unoptimized_defaults_enable_both_checks(self):
        self.assertEqual(profile([], "0", False), {})
        with self.assertRaisesRegex(ValueError, "explicit"):
            profile([], "0", True)

    def test_optimized_native_overflow_defaults_inherit_explicit_assertions(self):
        scalar = profile(["-Copt-level=s", "-Cdebug-assertions=on"], "s", False)
        self.assertNotIn("overflow-checks", scalar)
        with self.assertRaisesRegex(ValueError, "disabled"):
            profile(["-Copt-level=s"], "s", False)

    def test_wrong_profiles_cannot_pass_an_ordinary_test_audit(self):
        for flag in ["-Copt-level=3", "-Cdebuginfo=2", "-Cdebug-assertions=no", "-Coverflow-checks=no"]:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                profile([*self.arguments(), flag], "0", True)

    def test_macro_identity_retains_versions_and_feature_units(self):
        baseline = macro_key("derive-impl", "2.0.0", self.arguments())
        self.assertNotEqual(baseline, macro_key("derive-impl", "1.0.0", self.arguments()))
        self.assertNotEqual(baseline, macro_key("derive-impl", "2.0.0", self.arguments(feature="extra")))

    def test_capability_queries_are_not_macro_compilations(self):
        query = {"schema_version": 1, "arguments": ["rustc", "--crate-type=proc-macro", "--print=cfg"],
                 "environment": {}}
        result = native_macros([query, self.native()])
        self.assertEqual(len(result), 1)

    def test_ordinary_multi_output_crates_are_not_macro_compilations(self):
        library = {"schema_version": 1,
                   "arguments": ["rustc", "--crate-type", "rlib", "--crate-type=cdylib"],
                   "environment": {}}
        self.assertEqual(len(native_macros([library, self.native()])), 1)

    def test_two_versions_of_one_macro_are_checked_independently(self):
        versions = ["1.0.0", "2.0.0"]
        native = native_macros([self.native(version) for version in versions])
        result = match_macros([self.action(version) for version in versions],
                              [self.report(version) for version in versions], native)
        self.assertEqual([row["version"] for row in result], versions)

    def test_duplicate_native_units_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate native"):
            native_macros([self.native(), self.native()])

    def test_missing_configured_executed_or_native_units_are_rejected(self):
        native = native_macros([self.native()])
        for actions, reports, observed in [([], [self.report()], native), ([self.action()], [], native),
                                          ([self.action()], [self.report()], {}),
                                          ([self.action(), self.action()], [self.report()], native)]:
            with self.subTest(actions=actions, reports=reports), self.assertRaises(ValueError):
                match_macros(actions, reports, observed)

    def test_package_version_feature_and_edition_drift_is_rejected(self):
        native = native_macros([self.native()])
        for action, report in [(self.action("1.0.0"), self.report("1.0.0")),
                               (self.action(feature="extra"), self.report()),
                               ({"target_label": self.report()["label"], "arguments": self.arguments(edition="2024")}, self.report())]:
            with self.subTest(action=action), self.assertRaises(ValueError):
                match_macros([action], [report], native)

    def test_empty_and_unidentified_native_macro_inventories_are_rejected(self):
        invocation = self.native()
        invocation["environment"].pop("CARGO_PKG_VERSION")
        for invocations in [[], [invocation]]:
            with self.subTest(invocations=invocations), self.assertRaises(ValueError):
                native_macros(invocations)

    def test_generator_roles_come_from_native_artifacts_instead_of_filenames(self):
        target = {"kind": ["custom-build"], "src_path": "/build/source/crates/api/scripts/generate.rs"}
        message = {"reason": "compiler-artifact", "manifest_path": "/build/source/crates/api/Cargo.toml",
                   "target": target}
        self.assertEqual(generator_sources([message]), {"crates/api/scripts/generate.rs"})
        ordinary = {**message, "target": {"kind": ["bin"], "src_path": "/build/source/crates/api/src/bin/build.rs"}}
        self.assertFalse(generator_sources([ordinary]))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            generator_sources([message, message])

    def test_external_generator_artifacts_are_not_first_party_units(self):
        message = {"reason": "compiler-artifact", "manifest_path": "/nix/store/vendor/upstream/Cargo.toml",
                   "target": {"kind": ["custom-build"], "src_path": "/nix/store/vendor/upstream/build.rs"}}
        self.assertFalse(generator_sources([message]))


class NativeDefaultBindingTests(unittest.TestCase):
    def fixture(self):
        compiler = "bazel-out/native/rust/bin/rustc"
        digest = "a" * 64
        receipt = {"schema_version": 1, "status": "PASS", "native_target": "x86_64-unknown-linux-gnu",
                   "compiler": {"unwrapped": "/nix/store/compiler/bin/rustc.unwrapped"},
                   "tools_sha256": {"/nix/store/compiler/bin/rustc.unwrapped": digest}}
        actions = [{"arguments": [compiler, "--target=x86_64-unknown-linux-gnu"]}]
        events = [{"mnemonic": "Rustc", "inputs": [
            {"path": compiler, "digest": {"hash": digest, "hashFunctionName": "SHA-256"}},
        ]}]
        return receipt, actions, events

    def test_matches_executed_binary_digest_and_native_target(self):
        receipt, actions, events = self.fixture()
        result = bind_native_defaults(receipt, actions, events)
        self.assertEqual(result["actions"], 1)
        self.assertEqual(result["compiler_sha256"], "a" * 64)
        actions[0]["arguments"] = actions[0]["arguments"][:1]
        self.assertEqual(bind_native_defaults(receipt, actions, events)["status"], "PASS")

    def test_other_compilers_and_digest_algorithms_cannot_reuse_probes(self):
        for changed in [{"hash": "b" * 64}, {"hashFunctionName": "SHA-1"}]:
            receipt, actions, events = self.fixture()
            events[0]["inputs"][0]["digest"].update(changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "differs"):
                bind_native_defaults(receipt, actions, events)

    def test_missing_ambiguous_and_unexecuted_compilers_are_rejected(self):
        for mode in ["missing", "duplicate", "unexecuted", "empty"]:
            receipt, actions, events = self.fixture()
            if mode == "missing":
                events[0]["inputs"] = []
            elif mode == "duplicate":
                events[0]["inputs"] *= 2
            elif mode == "unexecuted":
                actions.append({"arguments": ["other/rustc"]})
            else:
                events = []
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                bind_native_defaults(receipt, actions, events)

    def test_failed_probes_and_foreign_targets_are_rejected(self):
        receipt, actions, events = self.fixture()
        actions[0]["arguments"][-1] = "--target=wasm32-unknown-unknown"
        with self.assertRaisesRegex(ValueError, "foreign"):
            bind_native_defaults(receipt, actions, events)

        receipt["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            bind_native_defaults(receipt, actions, events)


class NativeExecutionBindingTests(unittest.TestCase):
    def fixture(self):
        from inspect_compiler_execution import compilation_inventory

        requests = [{"schema_version": 1, "directory": "/source/crates/demo",
                     "arguments": ["rustc", "src/lib.rs"], "environment": {"CARGO_PKG_VERSION": "1.0.0"}}]
        defaults = {"compiler_sha256": "a" * 64}
        receipt = {"schema_version": 1,
                   "status": "PASS: requested compiler invocations reached the declared unwrapped compiler",
                   "tools": {"rustc": {"sha256": "a" * 64}},
                   "requested_compilation_inventory": compilation_inventory(requests),
                   "execution_capture": {"complete": True, "unresolved_task_records": []},
                   "inputs_sha256": {"execution": "b" * 64}}
        return requests, defaults, receipt

    def test_profiles_bind_to_observed_requests_and_the_probed_compiler(self):
        requests, defaults, receipt = self.fixture()
        result = bind_native_execution(receipt, requests, defaults)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["compilation_inventory"]["units"], 1)

    def test_failed_inspection_and_another_compiler_are_rejected(self):
        requests, defaults, receipt = self.fixture()
        with self.assertRaisesRegex(ValueError, "requires"):
            bind_native_execution(receipt, requests, None)
        with self.assertRaisesRegex(ValueError, "different compiler"):
            bind_native_execution(receipt, requests, {"compiler_sha256": "c" * 64})

        receipt["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            bind_native_execution(receipt, requests, defaults)

    def test_unobserved_duplicate_or_changed_source_requests_are_rejected(self):
        for mode in ["extra", "duplicate", "arguments", "environment", "directory"]:
            requests, defaults, receipt = self.fixture()
            if mode == "extra":
                requests.append({"arguments": ["rustc", "src/other.rs"]})
            elif mode == "duplicate":
                requests *= 2
            elif mode == "arguments":
                requests[0]["arguments"].append("-Copt-level=3")
            elif mode == "environment":
                requests[0]["environment"]["CARGO_PKG_VERSION"] = "2.0.0"
            else:
                requests[0]["directory"] = "/other/source"
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "differ from observed"):
                bind_native_execution(receipt, requests, defaults)

    def test_later_noncompiling_queries_do_not_change_the_source_inventory(self):
        requests, defaults, receipt = self.fixture()
        requests.append({"schema_version": 1, "arguments": ["rustc", "-vV"]})
        self.assertEqual(bind_native_execution(receipt, requests, defaults)["status"], "PASS")

    def test_requested_command_binding_preserves_incomplete_capture(self):
        requests, defaults, receipt = self.fixture()
        receipt["execution_capture"] = {
            "complete": False,
            "unresolved_task_records": [{"pid": 109, "record": "???( <detached ...>"}],
        }

        result = bind_native_execution(receipt, requests, defaults)

        self.assertFalse(result["execution_capture"]["complete"])
        self.assertEqual(result["execution_capture"], receipt["execution_capture"])


if __name__ == "__main__":
    unittest.main()

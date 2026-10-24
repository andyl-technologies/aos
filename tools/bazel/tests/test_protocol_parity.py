"""Rejects missing test targets and dependency-feature drift during conversion."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_pilot
import verify_protocol


class ProtocolParityTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.messages = self.root / "messages.jsonl"
        self.inventory = self.root / "inventory.json"
        self.label = "//crates/crucible/crucible-qemu-protocol:unit"
        self.events = [
            {
                "reason": "compiler-artifact",
                # Cargo omits the name when it matches the source directory.
                "package_id": "path+file:///source/crucible-qemu-protocol#0.1.0",
                "manifest_path": "/source/crucible-qemu-protocol/Cargo.toml",
                "target": {"kind": ["lib"], "name": "crucible_qemu_protocol"},
                "profile": {"test": True}, "executable": "/source/unit-tests", "features": [],
            },
            {
                "reason": "compiler-artifact", "package_id": "registry+https://example.invalid#serde@1.0.228",
                "target": {"kind": ["lib"]}, "profile": {"test": False}, "executable": None,
                "features": ["default", "derive"],
            },
        ]
        self.reports = [{
            "label": "@@+aos_tools_repository+aos_core_crates__serde-1.0.228//:serde",
            "kind": "rust_library", "features": ["derive", "default"],
            "tags": ["crate-name=serde"], "version": "1.0.228",
        }, {
            "label": self.label.removesuffix(":unit") + ":lib",
            "kind": "rust_library", "features": [],
        }]
        self.results = [{"identity": {"label": self.label}}]
        verification = patch.object(verify_protocol, "verify", return_value={})
        self.verify = verification.start()
        self.addCleanup(verification.stop)

    def compare(self, dependency_paths=None, allow_empty_tests=(), package_target_suffixes=None):
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))
        return verify_protocol.compare(
            self.root,
            self.inventory,
            self.messages,
            dependency_paths=dependency_paths,
            allow_empty_tests=allow_empty_tests,
            package_target_suffixes=package_target_suffixes,
        )

    def production_features(self, required_packages=()):
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        return verify_protocol.compare_features(
            self.inventory, self.messages,
            {"crucible-qemu-protocol": "crates/crucible/crucible-qemu-protocol"},
            required_packages=required_packages,
        )

    def test_resolved_profiles_retain_exact_external_features(self):
        for family in ["aos_cli_tests", "aos_cli_fleet_tests", "aos_cli_production", "qemu_gpl_production"]:
            with self.subTest(family=family):
                self.reports[0]["label"] = f"@@+aos_tools_repository+aos_{family}_crates__serde-1.0.228//:serde"
                result = self.production_features()
                self.assertEqual(result["features"], {"serde@1.0.228": [("default", "derive")]})

                self.reports[0]["features"].append("rc")
                with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
                    self.production_features()
                self.reports[0]["features"].remove("rc")

    def test_production_features_need_no_test_artifact_or_case_execution(self):
        self.events[0].pop("profile")
        self.events[0].pop("target")
        self.events[0].pop("executable")

        result = self.production_features(required_packages=["crucible-qemu-protocol"])

        self.assertEqual(result["features"], {"serde@1.0.228": [("default", "derive")]})
        self.verify.assert_not_called()

    def test_mixed_library_crate_types_retain_the_unit_test_oracle(self):
        self.events[0]["target"]["kind"] = ["cdylib", "rlib"]

        self.compare()

        self.assertEqual(self.verify.call_args.args[1], {self.label: Path("/source/unit-tests")})

    def test_shared_library_features_are_compared(self):
        self.reports[1]["kind"] = "rust_shared_library"
        self.production_features()

        self.reports[1]["features"] = ["unexpected"]
        with self.assertRaisesRegex(ValueError, "first-party Rust feature inventories differ"):
            self.production_features()

    def test_production_features_reject_test_feature_leakage(self):
        self.reports[0]["features"].append("rc")

        with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
            self.production_features()

    def test_production_features_preserve_both_compilation_units(self):
        self.events.append(dict(self.events[1], features=["default"]))
        self.reports.append(dict(self.reports[0], label=self.reports[0]["label"] + "__exec", features=["default"]))

        result = self.production_features()

        self.assertEqual(result["features"]["serde@1.0.228"], [("default",), ("default", "derive")])

    def test_production_features_require_selected_compiler_artifacts(self):
        with self.assertRaisesRegex(ValueError, "Cargo omitted first-party packages"):
            self.production_features(required_packages=["missing-library"])

    def test_one_package_variant_preserves_other_package_target_names(self):
        suffix = "_without_transfer"
        self.results[0]["identity"]["label"] += suffix
        second = dict(self.events[0])
        second.update({
            "package_id": "path+file:///source/crucible-qemu-shmem#0.1.0",
            "manifest_path": "/source/crucible-qemu-shmem/Cargo.toml",
        })
        self.events.append(second)
        other_label = "//crates/crucible/crucible-qemu-shmem:unit"
        self.results.append({"identity": {"label": other_label}})
        self.reports.append({
            "label": other_label.removesuffix(":unit") + ":lib",
            "kind": "rust_library", "features": [],
        })

        self.compare(package_target_suffixes={"crucible-qemu-protocol": suffix})

        self.assertEqual(set(self.verify.call_args.args[1]), {self.label + suffix, other_label})

    def test_package_variant_cannot_name_an_unselected_package(self):
        with self.assertRaisesRegex(ValueError, "unselected package"):
            self.compare(package_target_suffixes={"unknown": "_variant"})

    def test_native_foundation_repositories_preserve_exact_feature_checks(self):
        for family in ["native_foundation", "native_foundation_tests", "native_foundation_minimal"]:
            with self.subTest(family=family):
                self.reports[0]["label"] = f"@@+aos_tools_repository+aos_{family}_crates__serde-1.0.228//:serde"
                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()
                self.reports[0]["features"] = ["derive", "default"]

    def test_deployment_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_deployment_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_hub_portable_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_hub_portable_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_hub_model_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_hub_model_tests_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_hub_client_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_hub_client_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_release_preparation_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_release_preparation_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_hub_console_repositories_preserve_exact_feature_checks(self):
        for profile in ["hub_console", "hub_console_wasm"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_hub_native_repositories_preserve_exact_feature_checks(self):
        for profile in ["hub_native_postgres", "hub_native_tests"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_hub_worker_repositories_preserve_exact_feature_checks(self):
        for profile in ["hub_worker_tests", "hub_worker_all_features_tests", "hub_worker_wasm", "hub_worker_wasm_do_e2e", "hub_worker_wasm_all_features"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_hub_service_repositories_preserve_exact_feature_checks(self):
        for profile in ["hub_service", "hub_service_tests", "hub_service_all_features", "hub_service_all_features_tests"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_hub_db_repositories_preserve_exact_feature_checks(self):
        for profile in ["hub_db", "hub_db_tests", "hub_db_all_features", "hub_db_all_features_tests"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_package_manager_repositories_preserve_exact_feature_checks(self):
        for profile in ["package_manager", "package_manager_tests"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_boot_preparation_repositories_preserve_exact_feature_checks(self):
        for profile in ["boot_preparation", "boot_preparation_minimal"]:
            with self.subTest(profile=profile):
                self.reports[0]["label"] = "@@+aos_tools_repository+aos_" + profile + "_crates__serde-1.0.228//:serde"
                self.reports[0]["features"] = ["derive", "default"]

                self.compare()

                self.reports[0]["features"] = ["default"]
                with self.assertRaisesRegex(ValueError, "feature inventories differ"):
                    self.compare()

    def test_release_coordination_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_release_coordination_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_registry_native_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_registry_native_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_registry_native_tests_repositories_preserve_exact_feature_checks(self):
        self.reports[0]["label"] = "@@+aos_tools_repository+aos_registry_native_tests_crates__serde-1.0.228//:serde"

        self.compare()

        self.reports[0]["features"] = ["default"]
        with self.assertRaisesRegex(ValueError, "feature inventories differ"):
            self.compare()

    def test_explicit_empty_test_requires_an_empty_cargo_artifact(self):
        with patch.object(verify_protocol, "cases", return_value=[]):
            self.compare(allow_empty_tests=[self.label])

        self.assertEqual(self.verify.call_args.kwargs["allow_empty"], {self.label})
        with patch.object(verify_protocol, "cases", return_value=["present"]):
            with self.assertRaisesRegex(ValueError, "nonempty Cargo cases"):
                self.compare(allow_empty_tests=[self.label])

    def test_binary_only_package_has_libtests_without_a_doctest_target(self):
        self.events[0]["target"] = {"kind": ["bin"], "name": "probe"}
        label = self.label.replace(":unit", ":bin_probe")
        self.results[0]["identity"]["label"] = label
        self.reports[1].update(label=label + "_binary", kind="rust_binary", sources=["src/main.rs"])
        self.compare()
        log = self.root / "cargo-tests.log"
        log.write_text("running 1 test\ntest probe ... ok\n")
        packages = {"crucible-qemu-protocol": "crates/crucible/crucible-qemu-protocol"}

        result = verify_protocol.compare(
            self.root, self.inventory, self.messages, packages, cargo_log=log,
        )

        self.assertEqual(result["doctests"], {})
        self.results.append({"identity": {"label": self.label.replace(":unit", ":doc")}})
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))
        with self.assertRaisesRegex(ValueError, "doctest target inventories differ"):
            verify_protocol.compare(self.root, self.inventory, self.messages, packages, cargo_log=log)

    def test_empty_test_exception_cannot_name_an_absent_artifact(self):
        with self.assertRaisesRegex(ValueError, "no Cargo artifact"):
            self.compare(allow_empty_tests=[self.label + "_absent"])

    def test_first_party_dependencies_require_features_without_unselected_tests(self):
        self.events.append({
            **self.events[0], "package_id": "path+file:///source/shared#0.1.0",
            "manifest_path": "/source/shared/Cargo.toml", "profile": {"test": False},
            "executable": None, "features": ["checked"],
        })
        self.reports.append({"label": "//crates/shared:lib", "kind": "rust_library", "features": ["checked"]})

        result = self.compare({"shared": "crates/shared"})

        self.assertEqual(result["first_party_features"]["shared"], [("checked",)])
        self.reports[-1]["features"] = []
        with self.assertRaisesRegex(ValueError, "first-party Rust feature inventories differ"):
            self.compare({"shared": "crates/shared"})

    def test_empty_test_artifacts_require_an_explicit_parity_exception(self):
        binary = Path("/declared/bin-tests")
        label = "//fixture:bin_probe"
        (self.root / "index.json").write_text(json.dumps({"results": [{
            "identity": {"label": label}, "status": "PASSED", "outputs": {"test.xml": "empty.xml"},
        }]}))
        (self.root / "empty.xml").write_text('<testsuite tests="0" failures="0"/>')
        with patch.object(verify_pilot, "cases", return_value=[]):
            with self.assertRaisesRegex(ValueError, "test inventory differs"):
                verify_pilot.verify(self.root, {label: binary})
            result = verify_pilot.verify(self.root, {label: binary}, allow_empty={label})
        self.assertEqual(result["targets"][label], {"executed": [], "ignored": []})

    def test_ignored_suite_retains_cases_without_claiming_execution(self):
        label = "//fixture:live_service"
        (self.root / "index.json").write_text(json.dumps({"results": [{
            "identity": {"label": label}, "status": "PASSED", "outputs": {"test.xml": "ignored.xml"},
        }]}))
        (self.root / "ignored.xml").write_text('<testsuite tests="0" failures="0"/>')

        with patch.object(verify_pilot, "cases", return_value=["requires_service"]):
            result = verify_pilot.verify(self.root, {label: Path("/declared/live-tests")})

        self.assertEqual(result["targets"][label], {"executed": [], "ignored": ["requires_service"]})

    def test_cargo_short_path_identifiers_and_unordered_features_match(self):
        self.assertEqual(self.compare()["features"], {"serde@1.0.228": [("default", "derive")]})
        self.assertEqual(self.verify.call_args.args[1], {self.label: Path("/source/unit-tests")})

    def test_omitted_cargo_integration_target_fails(self):
        self.results.append({"identity": {"label": self.label.replace(":unit", ":codec")}})
        with self.assertRaisesRegex(ValueError, "integration target inventories differ"):
            self.compare()

    def test_first_party_feature_drift_fails(self):
        self.reports[1]["features"] = ["unexpected"]
        with self.assertRaisesRegex(ValueError, "first-party Rust feature inventories differ"):
            self.compare()

    def test_other_package_locations_use_the_same_parity_rules(self):
        self.events[0]["package_id"] = "path+file:///source/aos-core#0.1.0"
        self.events[0]["manifest_path"] = "/source/aos-core/Cargo.toml"
        label = "//crates/core/aos-core:unit"
        self.results[0]["identity"]["label"] = label
        self.reports[1]["label"] = "//crates/core/aos-core:lib"
        # Write the same fixture inputs, then select the other package root.
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))
        result = verify_protocol.compare(self.root, self.inventory, self.messages, {"aos-core": "crates/core/aos-core"})
        self.assertEqual(result["first_party_features"], {"aos-core": [()]})

    def test_omitted_cargo_example_fails(self):
        self.events.append({
            **self.events[0],
            "target": {"kind": ["example"], "name": "new-example"},
            "profile": {"test": False},
        })
        with self.assertRaisesRegex(ValueError, "example inventories differ"):
            self.compare()

    def test_feature_union_cannot_hide_distinct_compilation_variants(self):
        self.reports.append({**self.reports[0], "features": ["default"]})
        with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
            self.compare()

    def test_family_dependencies_keep_exact_feature_parity(self):
        label = self.reports[0]["label"]
        features = list(self.reports[0]["features"])
        for family in ["device", "store", "guest", "engine"]:
            with self.subTest(family=family):
                self.reports[0]["label"] = label.replace("aos_core_crates__", f"aos_{family}_crates__")
                self.reports[0]["features"] = list(features)
                self.assertEqual(self.compare()["features"], {"serde@1.0.228": [("default", "derive")]})

                self.reports[0]["features"].append("alloc")
                with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
                    self.compare()

    def test_store_dependency_build_metadata_retains_original_version(self):
        self.events[1]["package_id"] = "registry+https://example.invalid#zstd-sys@2.0.16+zstd.1.5.7"
        self.reports[0].update(
            label="@@+aos_tools_repository+aos_store_crates__zstd-sys-2.0.16-zstd.1.5.7//:zstd_sys",
            tags=["crate-name=zstd-sys"], version="2.0.16+zstd.1.5.7",
        )

        self.assertEqual(self.compare()["features"], {"zstd-sys@2.0.16+zstd.1.5.7": [("default", "derive")]})

    def test_external_crates_require_unambiguous_declared_package_identity(self):
        self.reports[0]["tags"] = []
        with self.assertRaisesRegex(ValueError, "exact package identity"):
            self.compare()

    def test_binary_libtests_and_feature_variant_suffixes_remain_in_inventory(self):
        binary = {**self.events[0], "target": {"kind": ["bin"], "name": "probe"}, "executable": "/source/bin-tests"}
        self.events.append(binary)
        self.results[0]["identity"]["label"] += "_test_support"
        binary_label = self.label.replace(":unit", ":bin_probe_test_support")
        self.results.append({"identity": {"label": binary_label}})
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))

        verify_protocol.compare(self.root, self.inventory, self.messages, target_suffix="_test_support")

        self.assertEqual(self.verify.call_args.args[1], {
            self.label + "_test_support": Path("/source/unit-tests"), binary_label: Path("/source/bin-tests"),
        })

    def test_unexpected_bazel_dependency_fails(self):
        unknown = self.reports[0]["label"].replace("serde-1.0.228", "unknown-1.0.0")
        self.reports.append({**self.reports[0], "label": unknown, "tags": ["crate-name=unknown"], "version": "1.0.0"})
        with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
            self.compare()

    def test_examples_preserve_the_selected_feature_variant(self):
        suffix = "_test_support"
        self.events.append({
            **self.events[0],
            "target": {"kind": ["example"], "name": "example"},
            "profile": {"test": False},
        })
        self.reports.append({
            "label": self.label.replace(":unit", ":example") + suffix,
            "kind": "rust_binary", "features": [],
            "sources": ["crates/crucible/crucible-qemu-protocol/examples/example.rs"],
        })
        self.results[0]["identity"]["label"] += suffix
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))

        result = verify_protocol.compare(self.root, self.inventory, self.messages, target_suffix=suffix)

        self.assertEqual(result["examples"], [self.reports[-1]["label"]])
        self.reports[-1]["label"] = self.reports[-1]["label"].removesuffix(suffix)
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        with self.assertRaisesRegex(ValueError, "example inventories differ"):
            verify_protocol.compare(self.root, self.inventory, self.messages, target_suffix=suffix)


class DoctestParityTests(unittest.TestCase):
    def test_package_variants_preserve_exact_doctest_target_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packages = {"first": "crates/shared/first", "second": "crates/shared/second"}
            summary = "test result: ok. 0 passed; 0 failed; 0 ignored;\n"
            (root / "cargo.log").write_text("Doc-tests first\n" + summary + "Doc-tests second\n" + summary)
            (root / "test.log").write_text(summary)
            labels = ["//crates/shared/first:doc_variant", "//crates/shared/second:doc"]
            results = [{"identity": {"label": label}, "status": "PASSED", "outputs": {"test.log": "test.log"}}
                       for label in labels]
            (root / "index.json").write_text(json.dumps({"results": results}))

            compared = verify_protocol.compare_doctests(
                root, root / "cargo.log", packages, package_target_suffixes={"first": "_variant"},
            )

            self.assertEqual(compared, dict.fromkeys(labels, {}))
            results[1]["identity"]["label"] += "_variant"
            (root / "index.json").write_text(json.dumps({"results": results}))
            with self.assertRaisesRegex(ValueError, "target inventories differ"):
                verify_protocol.compare_doctests(
                    root, root / "cargo.log", packages, package_target_suffixes={"first": "_variant"},
                )

    def test_item_qualified_doctests_preserve_the_item_and_compile_status(self):
        cargo = "test crucible/crucible-device/src/ninep/tree.rs - ninep::tree::qid_path (line 398) - compile ... ok\n"
        bazel = "test /build/workspace/crates/crucible/crucible-device/src/ninep/tree.rs - ninep::tree::qid_path (line 398) - compile ... ok\n"
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        expected = {"src/ninep/tree.rs - ninep::tree::qid_path (line 398) - compile": "ok"}
        package = "crates/crucible/crucible-device"
        self.assertEqual(verify_protocol.doctest_cases(cargo + summary, package), expected)
        self.assertEqual(verify_protocol.doctest_cases(bazel + summary, package), expected)

    def test_cargo_and_bazel_source_roots_normalize_with_compile_only_status(self):
        cargo = "test shared/example/src/lib.rs - (line 12) - compile ... ok\n"
        bazel = "test /build/workspace/crates/shared/example/src/lib.rs - (line 12) - compile ... ok\n"
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        self.assertEqual(
            verify_protocol.doctest_cases(cargo + summary, "crates/shared/example"),
            verify_protocol.doctest_cases(bazel + summary, "crates/shared/example"),
        )

    def test_ignored_cases_remain_distinct_from_successes(self):
        log = (
            "test crates/shared/example/src/lib.rs - (line 7) ... ignored, requires an external fixture\n"
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n"
        )
        self.assertEqual(
            verify_protocol.doctest_cases(log, "crates/shared/example"),
            {"src/lib.rs - (line 7)": "ignored"},
        )

    def test_summary_cannot_hide_missing_cases_or_foreign_sources(self):
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        with self.assertRaisesRegex(ValueError, "summaries do not match"):
            verify_protocol.doctest_cases(summary, "crates/shared/example")
        with self.assertRaisesRegex(ValueError, "outside the package"):
            verify_protocol.doctest_cases("test other/src/lib.rs - (line 7) ... ok\n" + summary, "crates/shared/example")

    def test_zero_case_docs_require_a_successful_summary(self):
        self.assertEqual(
            verify_protocol.doctest_cases("test result: ok. 0 passed; 0 failed; 0 ignored;\n", "crates/shared/example"), {},
        )
        with self.assertRaisesRegex(ValueError, "summaries do not match"):
            verify_protocol.doctest_cases("running 0 tests\n", "crates/shared/example")

    def test_generated_docs_require_declared_roots_and_preserve_ignored_status(self):
        package = "crates/shared/example"
        summary = "test result: ok. 0 passed; 0 failed; 1 ignored;\n"
        cargo = "test /build/target/example/out/api.rs - Api (line 7) ... ignored\n" + summary
        bazel = "test /build/bazel-out/bin/" + package + "/doc.runfiles/_main/" + package + "/generator.out_dir/api.rs - Api (line 7) ... ignored\n" + summary
        expected = {"src/generated/api.rs - Api (line 7)": "ignored"}
        self.assertEqual(verify_protocol.doctest_cases(cargo, package, {"/build/target/example/out": "src/generated"}), expected)
        self.assertEqual(verify_protocol.doctest_cases(bazel, package, {"generator.out_dir": "src/generated"}), expected)
        for log in [cargo, bazel]:
            with self.assertRaisesRegex(ValueError, "outside the package"):
                verify_protocol.doctest_cases(log, package)
        with self.assertRaisesRegex(ValueError, "invalid generated"):
            verify_protocol.doctest_cases(cargo.replace("out/api.rs", "out/../api.rs"), package,
                                         {"/build/target/example/out": "src/generated"})

    def test_generated_docs_reject_foreign_or_ambiguous_producers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            messages, inventory = root / "messages.jsonl", root / "inventory.json"
            event = {"reason": "build-script-executed", "package_id": "path+file:///build/example#example@1.0.0", "out_dir": "/build/target/example/out"}
            artifact = {"reason": "compiler-artifact", "package_id": event["package_id"], "manifest_path": "/build/source/crates/shared/example/Cargo.toml"}
            report = {"label": "//crates/shared/example:lib", "generated_inputs": {"crates/shared/example/generator.out_dir": "//crates/shared/example:generator"}}
            messages.write_text(json.dumps(artifact) + "\n" + json.dumps(event) + "\n")
            inventory.write_text(json.dumps({"configured_targets": [report]}))
            arguments = (messages, inventory, {"example": "crates/shared/example"}, {"example": "generator.out_dir"})
            self.assertEqual(verify_protocol.generated_doctest_sources(*arguments),
                             ({"example": {event["out_dir"]: "src/generated"}}, {"example": {"generator.out_dir": "src/generated"}}))
            messages.write_text(json.dumps(artifact) + "\n" + json.dumps(event) + "\n" + json.dumps({**event, "out_dir": "/build/other/out"}) + "\n")
            with self.assertRaisesRegex(ValueError, "unique Cargo"):
                verify_protocol.generated_doctest_sources(*arguments)
            messages.write_text(json.dumps(artifact) + "\n" + json.dumps(event) + "\n")
            report["generated_inputs"]["crates/shared/example/generator.out_dir"] = "//foreign:generator"
            inventory.write_text(json.dumps({"configured_targets": [report]}))
            with self.assertRaisesRegex(ValueError, "package-local producer"):
                verify_protocol.generated_doctest_sources(*arguments)


if __name__ == "__main__":
    unittest.main()

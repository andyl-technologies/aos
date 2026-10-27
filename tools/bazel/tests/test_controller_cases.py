"""Exercises complete controller case parity and its fail-closed boundaries."""

import copy
import unittest

from verify_controller_cases import compare_cases


class ControllerCaseTests(unittest.TestCase):
    def setUp(self):
        self.label = "//crates/crucible/crucible-engine:unit_controller_binary"
        self.executable = "/build/target/release/deps/crucible_engine-123"
        self.package_id = "path+file:///build/source/crates/crucible/crucible-engine#0.1.0"
        self.inventory = {
            "schema_version": 1,
            "configured_targets": [{
                "label": self.label,
                "crate_root": "crates/crucible/crucible-engine/src/lib.rs",
                "rustc_env": {"CARGO_PKG_NAME": "crucible-engine"},
            }],
        }
        self.discovery = {
            "schema_version": 1,
            "test_execution_qualified": False,
            "targets": {self.label: {"cases": ["runs", "manual"], "ignored": ["manual"]}},
        }
        self.messages = [{
            "reason": "compiler-artifact",
            "package_id": self.package_id,
            "manifest_path": "/build/source/crates/crucible/crucible-engine/Cargo.toml",
            "profile": {"test": True},
            "executable": self.executable,
            "target": {
                "name": "crucible_engine", "kind": ["lib"],
                "src_path": "/build/source/crates/crucible/crucible-engine/src/lib.rs",
            },
        }]
        self.suite = {
            "binary-id": "crucible-engine",
            "package-name": "crucible-engine",
            "package-id": self.package_id,
            "binary-path": self.executable,
            "binary-name": "crucible_engine",
            "kind": "lib",
            "build-platform": "target",
            "status": "listed",
            "testcases": {
                "runs": {"kind": "test", "ignored": False, "filter-match": {"status": "matches"}},
                "manual": {"kind": "test", "ignored": True, "filter-match": {"status": "mismatch", "reason": "ignored"}},
            },
        }
        self.nextest = {"test-count": 2, "rust-suites": {"crucible-engine": self.suite}}

    def compare(self):
        return compare_cases(self.inventory, self.discovery, self.messages, self.nextest)

    def test_matches_all_names_and_ignored_status_without_qualifying_execution(self):
        result = self.compare()

        self.assertFalse(result["test_execution_qualified"])
        self.assertEqual(result["targets"][self.label]["cases"], ["manual", "runs"])
        self.assertEqual(result["targets"][self.label]["ignored"], ["manual"])

    def test_rejects_equal_counts_with_different_case_names(self):
        self.discovery["targets"][self.label]["cases"] = ["different", "manual"]

        with self.assertRaisesRegex(ValueError, "cases or ignored cases differ"):
            self.compare()

    def test_rejects_changed_ignore_status(self):
        self.discovery["targets"][self.label]["ignored"] = []

        with self.assertRaisesRegex(ValueError, "ignored cases differ"):
            self.compare()

    def test_rejects_skipped_suite_even_if_its_case_list_is_retained(self):
        self.suite["status"] = "skipped-default-filter"

        with self.assertRaisesRegex(ValueError, "listing status differs"):
            self.compare()

    def test_rejects_nonignored_case_filtered_by_nextest(self):
        self.suite["testcases"]["runs"]["filter-match"] = {"status": "mismatch", "reason": "expression"}

        with self.assertRaisesRegex(ValueError, "unexpectedly filters"):
            self.compare()

    def test_rejects_nextest_executable_unbound_to_compiler_messages(self):
        self.suite["binary-path"] = "/build/target/release/deps/other-456"

        with self.assertRaisesRegex(ValueError, "unknown or duplicate Nextest"):
            self.compare()

    def test_rejects_nextest_package_identity_drift(self):
        self.suite["package-id"] += "-other"

        with self.assertRaisesRegex(ValueError, "suite identity"):
            self.compare()

    def test_rejects_compiler_artifact_missing_from_nextest(self):
        extra = copy.deepcopy(self.messages[0])
        extra["executable"] += "-extra"
        extra["target"]["src_path"] = "/build/source/crates/crucible/crucible-engine/tests/extra.rs"
        self.messages.append(extra)

        with self.assertRaisesRegex(ValueError, "binary inventories differ"):
            self.compare()

    def test_rejects_bazel_source_root_drift(self):
        self.inventory["configured_targets"][0]["crate_root"] = "crates/crucible/crucible-engine/tests/other.rs"

        with self.assertRaisesRegex(ValueError, "source has no Bazel binary"):
            self.compare()

    def test_rejects_duplicate_configured_binaries(self):
        self.inventory["configured_targets"].append(copy.deepcopy(self.inventory["configured_targets"][0]))

        with self.assertRaisesRegex(ValueError, "ambiguous Bazel"):
            self.compare()

    def test_rejects_duplicate_cargo_source_identity(self):
        extra = copy.deepcopy(self.messages[0])
        extra["executable"] += "-extra"
        self.messages.append(extra)

        with self.assertRaisesRegex(ValueError, "duplicate Cargo"):
            self.compare()

    def test_rejects_discovery_missing_its_configured_binary(self):
        self.inventory["configured_targets"] = []

        with self.assertRaisesRegex(ValueError, "reports omit"):
            self.compare()

    def test_rejects_case_summary_drift(self):
        self.nextest["test-count"] = 3

        with self.assertRaisesRegex(ValueError, "summary differs"):
            self.compare()

    def test_preserves_empty_binary(self):
        self.suite["testcases"] = {}
        self.nextest["test-count"] = 0
        self.discovery["targets"][self.label] = {"cases": [], "ignored": []}

        self.assertEqual(self.compare()["targets"][self.label]["cases"], [])

    def test_rejects_duplicate_listed_cases(self):
        self.discovery["targets"][self.label]["cases"] = ["manual", "runs", "runs"]

        with self.assertRaises(ValueError):
            self.compare()

    def test_rejects_execution_qualification_in_discovery(self):
        self.discovery["test_execution_qualified"] = True

        with self.assertRaisesRegex(ValueError, "unqualified for execution"):
            self.compare()


if __name__ == "__main__":
    unittest.main()

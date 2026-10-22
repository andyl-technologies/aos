"""Rejects missing test targets and dependency-feature drift during conversion."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_protocol


class ProtocolParityTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.messages = self.root / "messages.jsonl"
        self.inventory = self.root / "inventory.json"
        self.label = "//crates/crucible/protocol/crucible-qemu-protocol:unit"
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
        }, {
            "label": self.label.removesuffix(":unit") + ":lib",
            "kind": "rust_library", "features": [],
        }]
        self.results = [{"identity": {"label": self.label}}]
        verification = patch.object(verify_protocol, "verify", return_value={})
        self.verify = verification.start()
        self.addCleanup(verification.stop)

    def compare(self):
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))
        return verify_protocol.compare(self.root, self.inventory, self.messages)

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
        label = "//crates/shared/aos-core:unit"
        self.results[0]["identity"]["label"] = label
        self.reports[1]["label"] = "//crates/shared/aos-core:lib"
        # Write the same fixture inputs, then select the other package root.
        self.messages.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.inventory.write_text(json.dumps({"configured_targets": self.reports}))
        (self.root / "index.json").write_text(json.dumps({"results": self.results}))
        result = verify_protocol.compare(self.root, self.inventory, self.messages, {"aos-core": "crates/shared/aos-core"})
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

    def test_unexpected_bazel_dependency_fails(self):
        unknown = self.reports[0]["label"].replace("serde-1.0.228", "unknown-1.0.0")
        self.reports.append({**self.reports[0], "label": unknown})
        with self.assertRaisesRegex(ValueError, "resolved Rust feature inventories differ"):
            self.compare()


class DoctestParityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

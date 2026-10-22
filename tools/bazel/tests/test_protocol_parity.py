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


if __name__ == "__main__":
    unittest.main()

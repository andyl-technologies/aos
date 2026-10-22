"""Checks that family measurements cannot silently omit configured test targets."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "metadata"))
from measure_family import bazel_binaries, cargo_binaries


class FamilyMeasurementTests(unittest.TestCase):
    def events(self):
        return [
            {"id": {"namedSet": {"id": "current"}}, "namedSetOfFiles": {"files": [
                {"name": "crates/device/unit_binary", "uri": "file:///current/unit_binary"}]}},
            {"id": {"namedSet": {"id": "old"}}, "namedSetOfFiles": {"files": [
                {"name": "crates/device/unit_binary", "uri": "file:///old/unit_binary"}]}},
            {"id": {"targetCompleted": {"label": "//crates/device:unit_binary"}}, "completed": {
                "success": True, "outputGroup": [{"name": "default", "fileSets": [{"id": "current"}]}]}},
            {"id": {"buildFinished": {}}, "finished": {"exitCode": {"code": 0}}},
        ]

    def test_only_current_successful_outputs_are_selected(self):
        binaries = bazel_binaries(self.events(), ["//crates/device:unit_binary"])
        self.assertEqual(binaries, {"//crates/device:unit": Path("/current/unit_binary")})

    def test_missing_requested_target_rejects_measurement(self):
        with self.assertRaisesRegex(ValueError, "missing successful"):
            bazel_binaries(self.events(), ["//crates/device:unit_binary", "//crates/device:io_binary"])

    def test_unsuccessful_build_rejects_measurement(self):
        events = self.events()
        events[-1]["finished"]["exitCode"]["code"] = 1
        with self.assertRaisesRegex(ValueError, "missing successful"):
            bazel_binaries(events, ["//crates/device:unit_binary"])

    def test_cargo_library_and_integration_targets_remain_distinct(self):
        events = [{"reason": "compiler-artifact", "executable": "/target/" + name,
                   "profile": {"test": True}, "manifest_path": "/src/device/Cargo.toml",
                   "target": {"kind": [kind], "name": name}}
                  for kind, name in [("lib", "device"), ("test", "io")]]
        self.assertEqual(cargo_binaries(events, {"device": "crates/device"}), {
            "//crates/device:unit": Path("/target/device"), "//crates/device:io": Path("/target/io"),
        })

    def test_duplicate_cargo_artifact_rejects_measurement(self):
        event = {"reason": "compiler-artifact", "executable": "/target/device", "profile": {"test": True},
                 "manifest_path": "/src/device/Cargo.toml", "target": {"kind": ["lib"], "name": "device"}}
        with self.assertRaisesRegex(ValueError, "ambiguous Cargo"):
            cargo_binaries([event, event], {"device": "crates/device"})


if __name__ == "__main__":
    unittest.main()

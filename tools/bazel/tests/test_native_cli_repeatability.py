"""Exercises rejection controls for native CLI repeatability evidence."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_native_cli_repeatability import verify


class NativeCliRepeatabilityTests(unittest.TestCase):
    """Uses small synthetic records to test the verifier, not compiler parity."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.first = self.root / "first"
        self.second = self.root / "second"
        self.installed = self.root / "installed"
        self.repeated = self.root / "repeated"
        self.runtime = self.root / "runtime.json"
        names = ["aos", "apm", "apr", *[f"helper-{number}" for number in range(12)]]
        label = "//crates/cli/aos-cli:production_binaries"
        self.identifier = hashlib.sha256(label.encode()).hexdigest()
        artifacts = []
        for name in names:
            content = name.encode()
            destination = "bin/" + name
            artifacts.append({"destination": destination, "mode": "0755",
                              "sha256": hashlib.sha256(content).hexdigest()})
            for build in [self.first, self.second]:
                path = build / "packages" / self.identifier / "files" / destination
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            for package in [self.installed, self.repeated]:
                path = package / destination
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

        for build in [self.first, self.second]:
            self.write_json(build / "packages/index.json", {label: self.identifier})
            self.write_json(build / "packages" / self.identifier / "manifest.json", {"artifacts": artifacts})
            self.write_json(build / "inventory.json", {"fixture": True})
            self.write_json(build / "evidence/compiler-invocations.json", {"actions": ["synthetic-request"]})
            self.write_json(build / "evidence/execution.json", {
                "mnemonic": "Rustc", "runner": "linux-sandbox", "cacheHit": False, "exitCode": 0,
            })
        self.write_json(self.runtime, {"commands": {
            name: {"loader_exit_code": 0, **({"help_exit_code": 0} if name in {"aos", "apm", "apr"} else {})}
            for name in names
        }})

    @staticmethod
    def write_json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def run_verifier(self):
        return verify(self.first, self.second, self.installed, self.repeated, self.runtime)

    def test_complete_synthetic_records_pass(self):
        report = self.run_verifier()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["artifacts"]), 15)

    def test_same_build_cannot_supply_both_executions(self):
        with self.assertRaises(AssertionError):
            verify(self.first, self.first, self.installed, self.repeated, self.runtime)

    def test_different_compiler_requests_fail(self):
        self.write_json(self.second / "evidence/compiler-invocations.json", {"actions": ["different-request"]})
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_corrupt_exported_program_fails(self):
        (self.second / "packages" / self.identifier / "files/bin/apr").write_bytes(b"corrupt")
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_corrupt_installed_program_fails(self):
        (self.repeated / "bin/apr").write_bytes(b"corrupt")
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_cache_restoration_cannot_claim_uncached_execution(self):
        self.write_json(self.second / "evidence/execution.json", {
            "mnemonic": "Rustc", "runner": "linux-sandbox", "cacheHit": True, "exitCode": 0,
        })
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_equal_programs_with_private_sandbox_paths_fail(self):
        content = b"/build/bazel/sandbox/linux-sandbox/17/execroot/_main/generated/native.c"
        for build in [self.first, self.second]:
            package = build / "packages" / self.identifier
            (package / "files/bin/apr").write_bytes(content)
            manifest = json.loads((package / "manifest.json").read_text())
            for artifact in manifest["artifacts"]:
                if artifact["destination"] == "bin/apr":
                    artifact["sha256"] = hashlib.sha256(content).hexdigest()
            self.write_json(package / "manifest.json", manifest)
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_wrong_package_index_fails(self):
        self.write_json(self.second / "packages/index.json", {"wrong-label": self.identifier})
        with self.assertRaises(AssertionError):
            self.run_verifier()


if __name__ == "__main__":
    unittest.main()

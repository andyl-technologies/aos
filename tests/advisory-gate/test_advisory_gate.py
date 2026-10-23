"""Regression tests for the pinned advisory input validator."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "tools" / "advisory-gate.py"
SPEC = importlib.util.spec_from_file_location("advisory_gate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
advisory_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = advisory_gate
SPEC.loader.exec_module(advisory_gate)


class AdvisoryGateTests(unittest.TestCase):
    """Exercises rejection boundaries with a deliberately affected fixture."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "crates").mkdir()
        (self.repository / "pkgs").mkdir()
        (self.repository / "crates" / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "native-sys"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        (self.repository / "crates" / "secondary.lock").write_text(
            'version = 4\n\n[[package]]\nname = "clean"\nversion = "2.0.0"\n',
            encoding="utf-8",
        )
        (self.repository / "pkgs" / "native.nix").write_text(
            'let\n  version = "1.0.0";\nin version\n', encoding="utf-8"
        )
        self._write_json(
            "inventory.json",
            {
                "schema": "aos.native-advisory-inventory/v1",
                "components": [
                    {
                        "name": "native",
                        "version": "1.0.0",
                        "kind": "nix-literal",
                        "path": "pkgs/native.nix",
                        "field": "version",
                    },
                    {
                        "name": "bundled",
                        "version": "7.0.0",
                        "kind": "cargo-package",
                        "lock": "crates/Cargo.lock",
                        "package": "native-sys",
                        "package_version": "1.0.0",
                    },
                ],
            },
        )
        self._write_json(
            "snapshot.json",
            {
                "schema": "aos.advisory-snapshot/v1",
                "generated_on": "2026-10-22",
                "maximum_age_days": 31,
                "rustsec_revision": "fixture-revision",
                "native_findings": [],
            },
        )
        self._write_json(
            "exceptions.json",
            {"schema": "aos.advisory-exceptions/v1", "exceptions": []},
        )
        (self.repository / "cargo-report.jsonl").write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_json(self, name: str, value: object) -> None:
        (self.repository / name).write_text(
            json.dumps(value), encoding="utf-8"
        )

    def _arguments(self, today: str = "2026-10-22") -> argparse.Namespace:
        return argparse.Namespace(
            repository=self.repository,
            snapshot=self.repository / "snapshot.json",
            exceptions=self.repository / "exceptions.json",
            native_inventory=self.repository / "inventory.json",
            cargo_report=[self.repository / "cargo-report.jsonl"],
            lock=["crates/Cargo.lock", "crates/secondary.lock"],
            today=today,
        )

    def test_consistent_current_inputs_pass(self) -> None:
        advisory_gate.validate(self._arguments())

    def test_deliberately_affected_component_fails_without_disposition(self) -> None:
        self._write_json(
            "snapshot.json",
            {
                "schema": "aos.advisory-snapshot/v1",
                "generated_on": "2026-10-22",
                "maximum_age_days": 31,
                "rustsec_revision": "fixture-revision",
                "native_findings": [
                    {
                        "id": "FIXTURE-1",
                        "component": "native@1.0.0",
                        "fixed_version": "1.0.1",
                        "source": "https://example.invalid/FIXTURE-1",
                    }
                ],
            },
        )

        with self.assertRaisesRegex(
            advisory_gate.GateError, "findings lack active dispositions"
        ):
            advisory_gate.validate(self._arguments())

    def test_expired_disposition_fails(self) -> None:
        (self.repository / "cargo-report.jsonl").write_text(
            json.dumps(
                {
                    "type": "diagnostic",
                    "fields": {
                        "code": "vulnerability",
                        "advisory": {"id": "RUSTSEC-FIXTURE"},
                        "graphs": [{"Krate": {"name": "clean", "version": "2.0.0"}}],
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_json(
            "exceptions.json",
            {
                "schema": "aos.advisory-exceptions/v1",
                "exceptions": [
                    {
                        "id": "RUSTSEC-FIXTURE",
                        "component": "clean@2.0.0",
                        "owner": "fixture",
                        "reason": "fixture",
                        "remediation": "fixture",
                        "expires_on": "2026-10-21",
                    }
                ],
            },
        )

        with self.assertRaisesRegex(advisory_gate.GateError, "expired"):
            advisory_gate.validate(self._arguments())

    def test_resolved_component_cannot_keep_disposition(self) -> None:
        self._write_json(
            "exceptions.json",
            {
                "schema": "aos.advisory-exceptions/v1",
                "exceptions": [
                    {
                        "id": "RUSTSEC-FIXTURE",
                        "component": "clean@2.0.0",
                        "owner": "fixture",
                        "reason": "fixture",
                        "remediation": "fixture",
                        "expires_on": "2026-10-23",
                    }
                ],
            },
        )

        with self.assertRaisesRegex(
            advisory_gate.GateError, "dispositions do not match a current finding"
        ):
            advisory_gate.validate(self._arguments())

    def test_disposition_is_bound_to_exact_component_version(self) -> None:
        (self.repository / "cargo-report.jsonl").write_text(
            json.dumps(
                {
                    "type": "diagnostic",
                    "fields": {
                        "code": "vulnerability",
                        "advisory": {"id": "RUSTSEC-FIXTURE"},
                        "graphs": [
                            {"Krate": {"name": "clean", "version": "2.0.0"}}
                        ],
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_json(
            "exceptions.json",
            {
                "schema": "aos.advisory-exceptions/v1",
                "exceptions": [
                    {
                        "id": "RUSTSEC-FIXTURE",
                        "component": "clean@1.9.0",
                        "owner": "fixture",
                        "reason": "fixture",
                        "remediation": "fixture",
                        "expires_on": "2026-10-23",
                    }
                ],
            },
        )

        with self.assertRaisesRegex(
            advisory_gate.GateError,
            "findings lack active dispositions: RUSTSEC-FIXTURE for clean@2.0.0",
        ):
            advisory_gate.validate(self._arguments())

    def test_duplicate_target_findings_need_one_disposition(self) -> None:
        report = json.dumps(
            {
                "type": "diagnostic",
                "fields": {
                    "code": "vulnerability",
                    "advisory": {"id": "RUSTSEC-FIXTURE"},
                    "graphs": [
                        {"Krate": {"name": "clean", "version": "2.0.0"}}
                    ],
                },
            }
        )
        (self.repository / "cargo-report.jsonl").write_text(
            report + "\n", encoding="utf-8"
        )
        (self.repository / "second-report.jsonl").write_text(
            report + "\n", encoding="utf-8"
        )
        self._write_json(
            "exceptions.json",
            {
                "schema": "aos.advisory-exceptions/v1",
                "exceptions": [
                    {
                        "id": "RUSTSEC-FIXTURE",
                        "component": "clean@2.0.0",
                        "owner": "fixture",
                        "reason": "fixture",
                        "remediation": "fixture",
                        "expires_on": "2026-10-23",
                    }
                ],
            },
        )
        arguments = self._arguments()
        arguments.cargo_report.append(self.repository / "second-report.jsonl")

        advisory_gate.validate(arguments)

    def test_stale_snapshot_fails(self) -> None:
        with self.assertRaisesRegex(advisory_gate.GateError, "days old"):
            advisory_gate.validate(self._arguments(today="2026-11-23"))

    def test_scanner_execution_error_fails(self) -> None:
        (self.repository / "cargo-report.jsonl").write_text(
            json.dumps(
                {
                    "type": "log",
                    "fields": {
                        "level": "ERROR",
                        "message": "injected scanner failure",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(advisory_gate.GateError, "injected scanner failure"):
            advisory_gate.validate(self._arguments())

    def test_native_source_package_drift_fails(self) -> None:
        (self.repository / "crates" / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "native-sys"\nversion = "1.0.1"\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(advisory_gate.GateError, "source package drifted"):
            advisory_gate.validate(self._arguments())


if __name__ == "__main__":
    unittest.main()

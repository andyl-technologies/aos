"""Exercise reviewed authority installation and safe synchronization diagnostics.

The tests execute the actual generated guest programs with disposable public
inputs and controlled local child commands. They neither admit an authority nor
contact SQL, an issuer, a Worker or a provider.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


DIRECTORY = Path(__file__).parent
AUTHORITY = {"__name__": "authority_sync_fixture"}
LIFECYCLE = {"__name__": "authority_domain_fixture"}
for name, namespace in (("_hub-direct-authority.py", AUTHORITY),
                        ("_hub-direct-worker-lifecycle.py", LIFECYCLE)):
    path = DIRECTORY / name
    exec(compile(path.read_bytes(), str(path), "exec"), namespace)


class AuthorityControlSyncTests(unittest.TestCase):
    def setUp(self):
        self.retained = []
        self.driver_output = []
        AUTHORITY["retain_direct_flow"] = lambda name, result: self.retained.append((name, result))

    def guest(self, directory, *, installer=False):
        def command(machine, script, timeout):
            del machine
            marker = "INSTALL_WORKER_CONSUMERS" if installer else "NATIVE_AUTHORITY_CONTROL_SYNC"
            program = script.split("<<'" + marker + "'\n", 1)[1].rsplit(marker, 1)[0]
            if installer:
                # Only guest filesystem placement is redirected. The authority
                # projection, identity checks and create-only write are genuine.
                program = program.replace("/var/lib/hybrid-worker/controls", str(directory))
            result = subprocess.run([sys.executable, "-B", "-c", textwrap.dedent(program)],
                capture_output=True, timeout=timeout, check=False)
            if result.returncode:
                raise RuntimeError("controlled guest program refused")
            self.driver_output.append(result.stdout)
            return result.stdout.decode()
        return command

    def configuration(self, root):
        original = {"name": "public-fixture-worker", "scriptPath": "/public/fixture/shim.mjs",
            "resourcePersistencePath": "/public/fixture/state", "bindings": {},
            "durableObjects": {"HYBRID_AUTHORITY_STATE": {
                "className": "HybridAuthorityState", "useSQLite": True}},
            "kvNamespaces": {"TEST": "public-fixture-kv"},
            "queueProducers": {}, "queueConsumers": []}
        path = root / "original.json"
        path.write_text(json.dumps(original))
        consumer = {"HUB_EXTERNAL_OBJECT_CONSUMER": {
                "guard_namespace_id": "reviewed-public-namespace", "executor_identity": "reviewed-public-executor"},
            "HUB_EXTERNAL_STAGING_CONSUMER": {"domains": [{"issuer_installation": {
                "authority": {"guard_namespace_id": "reviewed-public-namespace"},
                "executor_identity": "reviewed-public-executor"}}]}}
        return original, path, consumer

    def test_installer_pins_selected_domain_and_preserves_it_on_final_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original, path, consumer = self.configuration(root)
            LIFECYCLE["private_guest_command"] = self.guest(root, installer=True)

            installed = LIFECYCLE["install_direct_worker_consumers"](
                None, sys.executable, str(path), consumer, {"external": {"address": "public-fixture"}})
            configuration = json.loads(Path(installed["configurationFile"]).read_bytes())
            self.assertEqual(configuration["bindings"]["HUB_EXTERNAL_GUARD_NAMESPACE_ID"],
                consumer["HUB_EXTERNAL_OBJECT_CONSUMER"]["guard_namespace_id"])
            self.assertEqual(configuration["bindings"]["HUB_EXTERNAL_STORAGE_EXECUTOR_ID"],
                consumer["HUB_EXTERNAL_OBJECT_CONSUMER"]["executor_identity"])
            for field in ("name", "scriptPath", "resourcePersistencePath", "durableObjects",
                          "kvNamespaces", "queueProducers", "queueConsumers"):
                self.assertEqual(configuration[field], original[field])
            self.assertEqual(stat.S_IMODE(Path(installed["configurationFile"]).stat().st_mode), 0o600)

            final = copy.deepcopy(consumer)
            final["HUB_EXTERNAL_COPY_CONSUMER"] = {"version": 2}
            repeated = LIFECYCLE["install_direct_worker_consumers"](None, sys.executable,
                installed["configurationFile"], final, {}, configuration_label="copy-list")
            final_configuration = json.loads(Path(repeated["configurationFile"]).read_bytes())
            for field in ("HUB_EXTERNAL_GUARD_NAMESPACE_ID", "HUB_EXTERNAL_STORAGE_EXECUTOR_ID"):
                self.assertEqual(final_configuration["bindings"][field], configuration["bindings"][field])
            self.assertEqual(final_configuration["durableObjects"], configuration["durableObjects"])

    def test_installer_refuses_missing_ledger_domain_mismatch_and_retargeting(self):
        for fault in ("ledger", "staging_domain", "retarget"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                original, path, consumer = self.configuration(root)
                if fault == "ledger":
                    original["durableObjects"] = {}
                elif fault == "staging_domain":
                    consumer["HUB_EXTERNAL_STAGING_CONSUMER"]["domains"][0]["issuer_installation"]["executor_identity"] = "different-executor"
                else:
                    original["bindings"]["HUB_EXTERNAL_GUARD_NAMESPACE_ID"] = "different-namespace"
                path.write_text(json.dumps(original))
                LIFECYCLE["private_guest_command"] = self.guest(root, installer=True)

                with self.assertRaisesRegex(RuntimeError, "controlled guest program refused"):
                    LIFECYCLE["install_direct_worker_consumers"](None, sys.executable,
                        str(path), consumer, {})
                self.assertFalse((root / "configuration-consumers.json").exists())
                self.assertEqual(json.loads(path.read_bytes()), original)

    def run_collector(self, root, program, expected=None, timeout=120):
        AUTHORITY["private_guest_command"] = self.guest(root)
        arguments = [sys.executable, "-B", "-c", program]
        return AUTHORITY["_run_authority_control_sync"](None, sys.executable, arguments,
            expected or {}, diagnostics_root=str(root / "diagnostics"), timeout_seconds=timeout)

    def test_sync_failure_retains_actual_child_result_without_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sentinel = "public-test-private-output-sentinel"
            program = "import sys\nsys.stdout.write(" + repr(sentinel) + ")\n" \
                + "sys.stderr.write('authority control returned status 503: ' + " + repr(sentinel) + ")\n" \
                + "sys.exit(7)\n"

            with self.assertRaisesRegex(RuntimeError, "authority_control_unavailable.*exit 7"):
                self.run_collector(root, program)
            result = json.loads((root / "diagnostics/result.json").read_bytes())
            self.assertEqual(self.retained[-1][1], result)
            self.assertEqual(result["exitCode"], 7)
            self.assertTrue(result["stdoutComplete"] and result["stderrComplete"])
            for name in ("stdout.private", "stderr.private", "result.json"):
                self.assertEqual(stat.S_IMODE((root / "diagnostics" / name).stat().st_mode), 0o600)
            self.assertEqual((root / "diagnostics/stdout.private").read_text(), sentinel)
            self.assertTrue(all(sentinel.encode() not in body for body in self.driver_output))

    def test_sync_bounds_timeout_and_launch_failure_never_supply_receipt(self):
        cases = (("overflow", "import os\nos.write(2, b'x' * 100000)\n", 120, "output_bound_exceeded"),
                 ("timeout", "import time\ntime.sleep(30)\n", 0.05, "synchronization_timeout"),
                 ("launch", None, 120, "launch_failure"))
        for name, program, timeout, category in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                AUTHORITY["private_guest_command"] = self.guest(root)
                arguments = [str(root / "missing-executable")] if program is None else [sys.executable, "-B", "-c", program]

                with self.assertRaisesRegex(RuntimeError, category):
                    AUTHORITY["_run_authority_control_sync"](None, sys.executable, arguments, {},
                        diagnostics_root=str(root / "diagnostics"), timeout_seconds=timeout)
                result = json.loads((root / "diagnostics/result.json").read_bytes())
                self.assertEqual(self.retained[-1][1], result)
                self.assertLessEqual(result["stdoutBytes"], 262144)
                self.assertLessEqual(result["stderrBytes"], 65536)
                if name == "overflow":
                    self.assertTrue(result["stderrOverflow"])
                    self.assertEqual((root / "diagnostics/stderr.private").stat().st_size, 65536)
                elif name == "timeout":
                    self.assertTrue(result["timedOut"])
                    self.assertIsNotNone(result["exitCode"])
                else:
                    self.assertIsNone(result["exitCode"])

    def test_sync_success_preserves_original_receipt_bytes_and_rejects_changed_receipt(self):
        expected = {"authority_id": "public-fixture-authority", "desired_generation": 1,
            "desired_digest": "a" * 64, "control_synchronized": True, "provider_readiness_evaluated": False}
        body = json.dumps(expected, indent=2) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            returned = self.run_collector(root, "import sys\nsys.stdout.write(" + repr(body) + ")\n", expected)
            self.assertEqual(returned, body.encode())
            self.assertEqual(self.retained[-1][1]["category"], "success")
            self.assertEqual(self.retained[-1][1]["exitCode"], 0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            changed = dict(expected, desired_generation=2)
            with self.assertRaisesRegex(RuntimeError, "receipt_mismatch"):
                self.run_collector(root, "print(" + repr(json.dumps(changed)) + ")", expected)
            self.assertEqual(self.retained[-1][1]["exitCode"], 0)
            self.assertTrue(all(b'desired_generation' not in value for value in self.driver_output[1:]))


if __name__ == "__main__":
    unittest.main()

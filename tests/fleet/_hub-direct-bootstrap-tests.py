"""Exercise readiness ordering, isolated state, and recorded epoch cleanup."""

import ast
import base64
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


FLOW_PATH = Path(__file__).with_name("_hub-direct-flow.py")
SPEC = importlib.util.spec_from_file_location("direct_flow", FLOW_PATH)
FLOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLOW)


def original_configuration():
    return {
        "resourcePersistencePath": "/var/lib/hybrid-worker/state",
        "namespaceObservationPath": "/var/lib/hybrid-worker/namespace-startup",
        "queueObservationPath": "/var/lib/hybrid-worker/queue-startup",
        "acceptanceSocketPath": "/var/lib/hybrid-worker/acceptance-control.sock",
        "scriptPath": "/nix/store/fixture/shim.mjs",
        "port": 4443,
        "bindings": {"HUB_STORAGE_WORK_KEY": "fixture-key", "console": {"version": "fixture"}},
        "queueConsumers": {"fixture": {"maxBatchSize": 2}},
    }


class BootstrapHarness:
    def __init__(self):
        self.events = []
        self.records = {}
        self.installed = None
        self.process = {"pid": 123, "startTicks": "456", "ownerUid": 0}
        self.tools = {
            "python": "fixture-python",
            "curl": "fixture-curl",
            "nativeOriginUrl": "https://native.fixture.test",
        }

    def install(self, machine, python, destination, body):
        self.events.append("install")
        self.installed = json.loads(body)
        return {
            "file": destination,
            "sha256": hashlib.sha256(body).hexdigest(),
            "byteSize": len(body),
        }

    def start(self, machine, tools, configuration, generation):
        self.events.append("start")
        body = json.dumps(self.installed, sort_keys=True, separators=(",", ":")).encode()
        self.process.update({
            "configurationSha256": hashlib.sha256(body).hexdigest(),
            "configurationFile": configuration,
            "generation": generation,
        })
        return self.process

    def retain(self, name, value):
        self.records[name] = value

    def stop(self, machine, python, process):
        self.assert_process = process
        self.events.append("stop")
        return {"status": "recorded_runner_disposed", "persistenceRemoved": False}

    def patches(self):
        stack = ExitStack()
        callbacks = {
            "read_direct_guest_file": lambda *args: json.dumps(original_configuration()).encode(),
            "_closed_review_json": json.loads,
            "install_direct_guest_file": self.install,
            "start_direct_worker": self.start,
            "retain_direct_flow": self.retain,
            "wait_worker_transport": lambda *args, **kwargs: self.events.append("worker-transport"),
            "private_guest_command": lambda *args, **kwargs: self.events.append("native-restart"),
            "wait_fixture_tls_response": lambda *args, **kwargs: (
                self.events.append("native-refusal") or {"body_base64": ""}),
            "stop_direct_worker": self.stop,
        }
        for name, callback in callbacks.items():
            stack.enter_context(patch.object(FLOW, name, callback, create=True))
        return stack


class WorkerBootstrapTests(unittest.TestCase):
    def test_state_is_disjoint_and_runtime_inputs_are_preserved(self):
        original = original_configuration()
        retained = copy.deepcopy(original)
        isolated = FLOW.isolated_prequalification_worker_configuration(original)

        self.assertEqual(original, retained)
        changed = {name for name in original if isolated[name] != original[name]}
        self.assertEqual(changed, {
            "resourcePersistencePath", "namespaceObservationPath", "queueObservationPath"})
        self.assertNotEqual(isolated["resourcePersistencePath"], original["resourcePersistencePath"])
        self.assertNotIn(original["resourcePersistencePath"], isolated["resourcePersistencePath"])
        isolated["bindings"]["console"]["version"] = "changed"
        self.assertEqual(original["bindings"]["console"]["version"], "fixture")

    def test_unselected_paths_refuse(self):
        for name in ("resourcePersistencePath", "acceptanceSocketPath"):
            configuration = original_configuration()
            configuration[name] = "/var/lib/other-state"
            with self.subTest(name=name), self.assertRaises(ValueError):
                FLOW.isolated_prequalification_worker_configuration(configuration)

    def test_order_and_stop_use_the_recorded_epoch(self):
        harness = BootstrapHarness()
        with harness.patches():
            with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original") as process:
                self.assertIs(process, harness.process)
                harness.events.extend(["native-trust", "input-review", "shared-control-review", "prebody"])

        self.assertEqual(harness.events, ["install", "start", "worker-transport", "native-restart",
            "native-refusal", "native-trust", "input-review", "shared-control-review", "prebody", "stop"])
        self.assertIs(harness.assert_process, harness.process)
        self.assertFalse(harness.records["prequalification-worker-stop.json"]["stop"]["persistenceRemoved"])

    def test_nonempty_native_refusal_stops_before_trust(self):
        harness = BootstrapHarness()
        with harness.patches(), patch.object(FLOW, "wait_fixture_tls_response",
                return_value={"body_base64": base64.b64encode(b"unexpected").decode()}):
            with self.assertRaisesRegex(ValueError, "refusal body differs"):
                with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original"):
                    self.fail("Trust must not run after a nonempty refusal")

        self.assertEqual(harness.events[-1], "stop")

    def test_start_retention_failure_still_stops(self):
        harness = BootstrapHarness()

        def refuse_start_record(name, value):
            if name == "prequalification-worker-start.json":
                raise OSError("controlled retention failure")
            harness.retain(name, value)

        with harness.patches(), patch.object(FLOW, "retain_direct_flow", refuse_start_record):
            with self.assertRaisesRegex(OSError, "controlled retention failure"):
                with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original"):
                    self.fail("Yield must not happen without retained start evidence")
        self.assertEqual(harness.events, ["install", "start", "stop"])

    def test_worker_refusal_failure_stops_before_native_restart(self):
        harness = BootstrapHarness()
        with harness.patches(), patch.object(
                FLOW, "wait_worker_transport", side_effect=ValueError("transport unavailable")):
            with self.assertRaisesRegex(ValueError, "transport unavailable"):
                with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original"):
                    self.fail("Native trust must wait for Worker transport")

        self.assertEqual(harness.events, ["install", "start", "stop"])
        self.assertNotIn("native-restart", harness.events)

    def test_cleanup_failure_refuses_an_otherwise_successful_epoch(self):
        harness = BootstrapHarness()
        with harness.patches(), patch.object(
                FLOW, "stop_direct_worker", side_effect=RuntimeError("cleanup incomplete")):
            with self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
                with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original"):
                    harness.events.append("trust-complete")

        self.assertNotIn("prequalification-worker-stop.json", harness.records)

    def test_cleanup_failure_preserves_the_producer_error(self):
        harness = BootstrapHarness()
        producer = ValueError("controlled producer failure")
        with harness.patches(), patch.object(FLOW, "stop_direct_worker",
                side_effect=RuntimeError("controlled cleanup failure")):
            with self.assertRaises(ValueError) as caught:
                with FLOW.direct_prequalification_worker("native", "worker", harness.tools, "original"):
                    raise producer

        self.assertIs(caught.exception, producer)
        self.assertFalse(harness.records["prequalification-worker-cleanup-failure.json"]["cleanupComplete"])
        self.assertTrue(producer.__notes__)

    def test_actual_flow_keeps_reviews_inside_epoch_and_new_namespace_after_stop(self):
        tree = ast.parse(FLOW_PATH.read_text())
        flow = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "run_external_direct_fleet")
        epoch = next(node for node in flow.body if isinstance(node, ast.With))
        called_inside = {node.func.id for node in ast.walk(epoch)
                         if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue({"observe_direct_native_trust", "await_direct_review",
            "install_direct_shared_controls", "run_direct_native_prebody_probes"} <= called_inside)
        after = flow.body[flow.body.index(epoch) + 1:]
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "initialize_direct_worker_controls"
            for statement in after for node in ast.walk(statement)))
        self.assertNotIn("initialize_direct_worker_controls", called_inside)


if __name__ == "__main__":
    unittest.main()

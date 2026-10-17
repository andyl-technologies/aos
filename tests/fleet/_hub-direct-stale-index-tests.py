"""Controlled process-custody and controller gates, not installed Hub evidence."""

import hashlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, file):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


process = load("stale_process", "_hub-direct-stale-index-process.py")
controller = load("stale_controller", "_hub-direct-stale-index.py")
placement = load("stale_placement", "_hub-direct-stale-placement.py")


class ProcessCustody(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="aos-index-process-controlled-")
        self.root = Path(self.private.name)
        self.environment = dict(os.environ)
        self.environment.update({"HUB_HYBRID_WORKER_URL": "https://controlled.test",
            "HUB_DEPLOYMENT_ID": "controlled", "HUB_STORAGE_WORK_KEY_FILE": "/controlled/key",
            "HUB_DATABASE_URL_FILE": "/controlled/database"})
        self.child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(120)"],
            env=self.environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.pin = process.process_identity(self.child.pid)

    def tearDown(self):
        if self.child.poll() is None:
            self.child.kill()
            self.child.wait()
        self.private.cleanup()

    def capture(self):
        selected = {key: self.pin[key] for key in ("pid", "startTicks", "ownerUid", "executableSha256")}
        selected["journalCursor"] = "controlled-existing-cursor"
        return process.capture_environment(selected, self.root / "environment.private")

    def test_actual_proc_environment_matches_exact_inherited_home(self):
        captured = self.capture()
        actual = process.checked_environment(captured, sys.executable)
        self.assertEqual(actual, self.environment)
        self.assertEqual(actual["HOME"], os.environ["HOME"])
        self.assertEqual(captured["nativeProcess"], self.pin)
        self.assertEqual(Path(captured["file"]).stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(captured), {"version", "file", "sha256", "bytes", "nativeProcess"})

    def test_changed_retained_bytes_or_permissions_refuse(self):
        captured = self.capture()
        file = Path(captured["file"])
        file.write_bytes(file.read_bytes() + b"EXTRA=changed\0")
        with self.assertRaisesRegex(ValueError, "changed"):
            process.checked_environment(captured, sys.executable)
        captured = process.capture_environment(self.pin, self.root / "second.private")
        Path(captured["file"]).chmod(0o644)
        with self.assertRaisesRegex(ValueError, "custody"):
            process.checked_environment(captured, sys.executable)

    def test_substituted_executable_or_symlink_refuse(self):
        captured = self.capture()
        other = self.root / "other-executable"
        other.write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "executable changed"):
            process.checked_environment(captured, other)
        link = self.root / "link"
        link.symlink_to(captured["file"])
        with self.assertRaises(OSError):
            process.checked_environment({**captured, "file": str(link)}, sys.executable)

    def test_wrong_original_pin_and_dead_lifetime_refuse(self):
        with self.assertRaisesRegex(ValueError, "lifetime"):
            process.capture_environment({**self.pin, "startTicks": "0"}, self.root / "wrong")
        captured = self.capture()
        self.child.kill()
        self.child.wait()
        with self.assertRaises((OSError, ValueError)):
            process.checked_environment(captured, sys.executable)

    def test_owner_selection_is_exact_and_root_observer_is_distinct(self):
        with self.assertRaisesRegex(ValueError, "lifetime"):
            process.capture_environment({**self.pin, "ownerUid": self.pin["ownerUid"] + 1}, self.root / "owner")
        incomplete = {key: value for key, value in self.pin.items() if key != "ownerUid"}
        with self.assertRaisesRegex(ValueError, "lifetime"):
            process.capture_environment(incomplete, self.root / "missing-owner")
        with patch.object(process.os, "getuid", return_value=0), patch.object(process.os, "geteuid", return_value=0):
            self.assertTrue(process._may_observe_owner(802))
        with patch.object(process.os, "getuid", return_value=1000), patch.object(process.os, "geteuid", return_value=1000):
            self.assertFalse(process._may_observe_owner(802))


class ControllerGates(unittest.TestCase):
    def fixture(self):
        tables = {name: [] for name in placement.STALE_INDEX_TABLES}
        tables.update({"packages": [["controlled-package"]], "releases": [["signed-release"]],
            "channels": [["stable"]], "index": [["fresh", None, "a" * 64, 1, 2, 3, 4, 5, 6]]})
        tools = {"staleIndexSqlQuery": lambda _: [[3, 4, 5, 6, "deployment_r2", "controlled/"]],
            "staleIndexReadIndex": lambda _: tables, "staleIndexRetain": lambda *args: None,
            "staleIndexInstallation": {"root": "/controlled"}, "staleIndexEnvironmentCapture": {},
            "staleIndexProcess": str(Path(process.__file__)), "deploymentId": "controlled",
            "aosHub": "/controlled/installed/aos-hub", "python": sys.executable}
        registry = {"registry": {"slug": "controlled/registry"}, "placement": {"name": "primary"}}
        return tables, tools, registry

    def test_absent_or_inexact_current_sql_never_arms_or_launches(self):
        for rows in ([], [[3, 4, 5, 6, "deployment_r2"]], [[3, 4, 5, 2**53, "deployment_r2", "p"]]):
            _, tools, registry = self.fixture()
            tools["staleIndexSqlQuery"] = lambda _, rows=rows: rows
            with patch.object(controller, "_guest") as guest:
                with self.assertRaises(ValueError):
                    controller.run_direct_stale_index_case(None, None, None, None,
                        tools, None, registry, {"sourceCommit": "a" * 64}, None)
                guest.assert_not_called()

    def test_nonfresh_or_different_signed_source_never_arms(self):
        tables, tools, registry = self.fixture()
        tables["index"][0][2] = "b" * 64
        with patch.object(controller, "_guest") as guest:
            with self.assertRaisesRegex(ValueError, "fresh signed"):
                controller.run_direct_stale_index_case(None, None, None, None,
                    tools, None, registry, {"sourceCommit": "a" * 64}, None)
            guest.assert_not_called()

    def test_whole_window_capacity_refusal_or_evidence_overflow_never_arms(self):
        for observed in ({"overflow": True, "capacityRefusals": 0},
                         {"overflow": False, "capacityRefusals": 1}):
            _, tools, registry = self.fixture()
            with patch.object(controller, "_guest", return_value=observed) as guest:
                with self.assertRaisesRegex(ValueError, "whole-window"):
                    controller.run_direct_stale_index_case(None, None, None, None,
                        tools, None, registry, {"sourceCommit": "a" * 64}, None)
                self.assertEqual(guest.call_count, 1)
                self.assertEqual(guest.call_args.args[3]["request"]["kind"], "transport-status")

    def test_guest_program_preserves_actual_source_and_compiles(self):
        class Agent:
            def request(self, command, timeout):
                self.command = command.decode()
                self.timeout = timeout
                return 0, b'{"controlled":true}', b''

        class Machine:
            agent = Agent()

        result = controller._guest(Machine, {"python": sys.executable}, "control", {"private": "input"})
        self.assertEqual(result, {"controlled": True})
        program = Machine.agent.command.split("\n", 1)[1].rsplit("STALE_INDEX_PROGRAM", 1)[0]
        compile(program, "actual-embedded-stale-index", "exec")
        self.assertEqual(Machine.agent.timeout, 45)
        self.assertTrue(program.startswith(Path(controller.__file__).read_text()))

    def test_controlled_complete_sequence_uses_retained_original_and_public_cas(self):
        before, tools, registry = self.fixture()
        after = json.loads(json.dumps(before))
        error = "storage placement or binding changed during Worker execution"
        after["index"][0][:2] = ["failed", error]
        reads = iter([before, after])
        tools["staleIndexReadIndex"] = lambda _: next(reads)
        tools["stalePlacementHelper"] = str(Path(placement.__file__))
        events = []
        receipts = []
        tools["staleIndexRetain"] = lambda name, value: receipts.append((name, value))
        now = int(time.time())
        body = json.dumps({"version": 1, "plan_id": "controlled-original", "issued_at": now,
            "expires_at": now + 30, "placement_id": 3, "placement_resource_version": 4,
            "placement_prefix": "controlled/", "operation": {"kind": "inspect_metadata", "path": "info/refs"}}).encode()
        digest = hashlib.sha256(body).hexdigest()
        held = {"version": 1, "state": "held", "requestSha256": digest,
            "signatureSha256": "b" * 64, "planIdSha256": hashlib.sha256(b"controlled-original").hexdigest(),
            "bodyBytes": str(len(body)), "expiresAtUnixSeconds": str(now + 30),
            "observedAtUnixMillis": str(now * 1000)}

        class Controls:
            def __init__(self):
                self.current = {"name": "primary", "prefix": "controlled/", "bindingName": "binding",
                    "resourceVersion": "4", "spec": {"readOrder": "0", "desiredState": "active",
                        "desiredReadEnabled": True}, "status": {"effectiveReadEnabled": True}}

            def call(self, service, method, request):
                events.append(method)
                self.assert_request(request)
                return {"placement": json.loads(json.dumps(self.current))}

            def assert_request(self, request):
                if request["surface"] != {"registrySlug": "controlled/registry"}:
                    raise AssertionError("incorrect actual surface request")

            def reviewed(self, service, plan, apply, request, label):
                events.append((plan, apply))
                self.assert_request(request)
                if request["expectedResourceVersion"] != "4" or request["updateMask"] != ["read_order"]:
                    raise AssertionError("incorrect reviewed pins")
                self.current["resourceVersion"] = "5"
                self.current["spec"]["readOrder"] = request["readOrder"]
                return {"placement": json.loads(json.dumps(self.current))}

        def guest(machine, selected_tools, action, value):
            if action == "control":
                kind = value["request"]["kind"]
                events.append(kind)
                if kind == "transport-status":
                    return {"overflow": False, "capacityRefusals": 0}
                return held if kind == "status" else {"version": 1, "state": kind}
            events.append(action)
            if action == "launch-index":
                return {"root": "/controlled/index", "supervisor": {"pid": 1}}
            if action == "advance":
                return {"bodyBase64": base64.b64encode(body).decode()}
            if action == "index-terminal":
                return {"exitCode": 1, "timedOut": False, "stderrBase64": base64.b64encode(error.encode()).decode()}
            raise AssertionError("unexpected guest action")

        with tempfile.TemporaryDirectory(prefix="aos-index-controller-controlled-") as root:
            tools["staleIndexControllerRoot"] = str(Path(root) / "original")
            with patch.object(controller, "_guest", side_effect=guest):
                result = controller.run_direct_stale_index_case(None, None, None, None,
                    tools, Controls(), registry, {"sourceCommit": "a" * 64}, None)
            retained = Path(tools["staleIndexControllerRoot"]) / "original-request.private.json"
            self.assertEqual(retained.read_bytes(), body)
        self.assertEqual(events, ["transport-status", "arm", "launch-index", "status", "advance", "GetPlacement",
            ("PlanUpdatePlacement", "UpdatePlacement"), "GetPlacement", "release", "index-terminal",
            "transport-status", "close"])
        self.assertEqual(result["verdict"]["outcome"], "native_stale_result_refused")
        self.assertIsNone(result["providerRequests"])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertEqual([name for name, _ in receipts], ["actual-stale-index-case.private.json"])


if __name__ == "__main__":
    unittest.main()

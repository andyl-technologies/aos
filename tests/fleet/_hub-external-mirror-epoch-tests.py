"""Controlled successor input and actual lifecycle ordering regressions."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_epoch", Path(__file__).with_name("_hub-external-mirror-epoch.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    root = "/var/lib/hybrid-native/external-oci/" + "a" * 32
    original = {"version": 1, "placementId": 7, "placementPrefix": "original/registry",
        "files": {"guardKeyFile": root + "/physical-key", "workKeyFile": root + "/work-key",
            "direct": {"acceptanceFile": root + "/direct.json"}},
        **{field: root + "/inventory-restart-" + suffix + ".json"
            for field, suffix in (("readinessFile", "ready"), ("terminalFile", "terminal"),
                ("shutdownFile", "shutdown"))}}
    triplet = {"artifactFile": root + "/mirror-review/artifact.json",
        "reviewerPublicKeyFile": root + "/mirror-review/reviewer.hex",
        "guardKeyFile": root + "/mirror-key"}
    return root, original, triplet


class MirrorEpochTests(unittest.TestCase):
    def test_only_selected_triplet_and_observation_paths_change(self):
        root, original, triplet = fixture()
        before = copy.deepcopy(original)
        result = module.external_mirror_successor_input(original, root, triplet)
        restored = copy.deepcopy(result)
        del restored["files"]["mirrorFunctional"]
        for field in ("readinessFile", "terminalFile", "shutdownFile"):
            self.assertTrue(result[field].startswith(root + "/mirror-functional-"))
            restored[field] = original[field]
        self.assertEqual(restored, original)
        self.assertEqual(original, before)
        self.assertEqual(result["files"]["mirrorFunctional"], triplet)

    def test_wrong_epoch_and_unowned_or_reused_roles_refuse(self):
        root, original, triplet = fixture()
        for changed in ({**triplet, "guardKeyFile": original["files"]["guardKeyFile"]},
                {**triplet, "guardKeyFile": original["files"]["workKeyFile"]},
                {**triplet, "artifactFile": "/tmp/other.json"},
                {**triplet, "artifactFile": root + "/../other.json"},
                {**triplet, "approved": True}):
            with self.assertRaises(ValueError):
                module.external_mirror_successor_input(original, root, changed)
        with self.assertRaises(ValueError):
            module.external_mirror_successor_input({**original,
                "readinessFile": root + "/helper-ready.json"}, root, triplet)
        with self.assertRaises(ValueError):
            module.external_mirror_successor_input({**original, "files": {
                **original["files"], "mirrorFunctional": triplet}}, root, triplet)

    def run_transition(self, *, shutdown_error=False, constructor_error=False):
        root, original, triplet = fixture()
        raw = json.dumps(original).encode()
        old = {"executableSha256": "b" * 64, "pid": 1}
        new = {"executableSha256": "b" * 64, "pid": 2}
        ready = {"identity": {"expiresAt": 500, "candidateSha256": "c" * 64},
            "backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}}
        helper = {"input": {"file": root + "/inventory-restart-input.json",
            "sha256": hashlib.sha256(raw).hexdigest()}, "inputValue": original,
            "process": old, "readiness": ready}
        events, ownership = [], {"helper": helper, "processes": {"native": old, "worker": {}}}
        module.read_direct_guest_file = lambda *args: raw
        module.install_direct_guest_file = lambda machine, python, path, body: {
            "file": path, "sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}
        def stop(*args):
            events.append("old-exit")
            if shutdown_error:
                raise RuntimeError("controlled shutdown refusal")
            return {"controlledExit": True}
        def launch(*args):
            events.append("new-launch")
            self.assertIsNone(ownership["helper"])
            self.assertNotIn("native", ownership["processes"])
            return new
        def await_ready(*args, **kwargs):
            events.append("new-constructor")
            self.assertEqual(ownership["processes"]["native"], new)
            self.assertEqual(kwargs["readiness_file"], root + "/mirror-functional-ready.json")
            if constructor_error:
                raise RuntimeError("controlled constructor refusal")
            return ready
        module.shutdown_external_oci_helper = stop
        module.launch_managed_process = launch
        module.await_external_oci_helper = await_ready
        module.select_external_storage_codec = lambda *args, **kwargs: {"controlledCodec": True}
        module.retain_direct_flow = lambda *args: events.append("retained")
        class Workflow:
            boundaries = {}
            def close(self, processes):
                events.append("close-producer")
            def resume(self, prepared, processes, role):
                events.append("resume-successor")
        try:
            result = module.restart_external_mirror_native(None, {"python": "selected-python",
                "managedCleanupNativeHelper": "selected-helper"},
                {"coordinates": {"nativeRoot": root, "runId": "a" * 32}},
                {"native": old, "worker": {}}, helper, triplet, Workflow(), {}, ownership)
        except RuntimeError:
            result = None
        return events, ownership, result

    def test_old_exit_then_new_constructor_then_capture_resume(self):
        events, ownership, result = self.run_transition()
        self.assertEqual(events, ["close-producer", "old-exit", "new-launch",
            "new-constructor", "resume-successor", "retained"])
        self.assertEqual(result["helper"]["previousEpochExit"], {"controlledExit": True})
        self.assertEqual(ownership["helper"]["process"]["pid"], 2)
        self.assertIsNone(result["helper"]["remoteDrain"])

    def test_shutdown_or_constructor_failure_never_resumes_and_keeps_owned_pin(self):
        events, ownership, result = self.run_transition(shutdown_error=True)
        self.assertIsNone(result)
        self.assertEqual(events, ["close-producer", "old-exit"])
        self.assertEqual(ownership["processes"]["native"]["pid"], 1)
        events, ownership, result = self.run_transition(constructor_error=True)
        self.assertIsNone(result)
        self.assertEqual(events[-1], "new-constructor")
        self.assertNotIn("resume-successor", events)
        self.assertEqual(ownership["processes"]["native"]["pid"], 2)
        self.assertIsNone(ownership["helper"])
        self.assertIn("partialHelperInput", ownership)


if __name__ == "__main__":
    unittest.main()

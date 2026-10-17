"""Controlled private renderer and complete transfer commitment regressions."""

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = load("mirror_observations", "_hub-external-mirror-observations.py")
renderer = load("mirror_private_renderer", "_hub-direct-worker-lifecycle.py")


class MirrorObservationsTests(unittest.TestCase):
    def test_real_private_renderer_compiles_the_complete_actor_and_journal_actions(self):
        programs = []
        def capture(machine, command, timeout):
            program = command.split("<<'DIRECT_PRIVATE_ACTION'\n", 1)[1].rsplit("\nDIRECT_PRIVATE_ACTION", 1)[0]
            compile(program, "actual-private-rendered-action", "exec")
            programs.append(program)
            return '{}'
        renderer.private_guest_command = capture
        module.direct_guest_python = renderer.direct_guest_python
        tools = {name: "/nix/store/" + "a" * 32 + "-selected/bin/" + name for name in (
            "python", "nixStore", "managedCleanupNativeHelper", "hub", "wasm", "shim", "runner",
            "workerd", "providerConformance")}
        tools.update(commonSourceStorePath="/nix/store/selected-common", workerSourcePath="/nix/store/selected-worker",
            nativeSourcePath="/nix/store/selected-native", workerDistribution="/nix/store/selected-distribution")
        module.capture_external_mirror_native(None, tools, {"coordinates": {"nativeRoot": "/controlled"}}, {
            "process": {"controlledProcessPin": True}, "input": {"file": "/controlled/input", "sha256": "b" * 64},
            "inputValue": {"readinessFile": "/controlled/ready"}})
        self.assertEqual(len(programs), 1)
        self.assertNotIn('\x00', programs[0])
        self.assertIn("argv.split(b'\\x00')", programs[0])
        self.assertIn("'--query','--deriver'", programs[0])
        with self.assertRaises(KeyError):
            module.copy_external_mirror_provider_journal(None, None, tools, "/controlled", "/journal")
        self.assertEqual(len(programs), 2)
        self.assertIn("followlinks=False", programs[1])

    def test_reference_is_numeric_and_cannot_borrow_an_unsafe_path_or_empty_file(self):
        selected = {"file": "/private/selected.json", "sha256": "a" * 64, "byteSize": "123"}
        self.assertEqual(module.mirror_review_reference(selected), {
            "path": "/private/selected.json", "sha256": "a" * 64, "byteSize": 123})
        for changed in ({**selected, "file": "/private/../other"},
                {**selected, "file": "relative"}, {**selected, "byteSize": True},
                {**selected, "byteSize": "0"}, {**selected, "sha256": "wrong"}):
            with self.assertRaises(ValueError):
                module.mirror_review_reference(changed)

    def test_journal_changed_after_inventory_refuses_before_copy(self):
        module.direct_guest_python = lambda *args, **kwargs: json.dumps({"files": [{
            "path": "original.json", "sha256": hashlib.sha256(b"original").hexdigest(), "byteSize": 8}],
            "byteSize": 8})
        module.read_direct_guest_file = lambda *args: b"changed!"
        writes = []
        module.install_direct_guest_file = lambda *args: writes.append(args)
        with self.assertRaisesRegex(ValueError, "changed before private transfer"):
            module.copy_external_mirror_provider_journal(None, None, {"python": "selected-python"},
                "/controlled", "/actual-journal")
        self.assertEqual(writes, [])


if __name__ == "__main__":
    unittest.main()

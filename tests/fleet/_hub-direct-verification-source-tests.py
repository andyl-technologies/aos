"""Check initial source selection and rendered consumer installation syntax."""

import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


HERE = Path(__file__).parent


def load(name, leaf):
    specification = importlib.util.spec_from_file_location(name, HERE / leaf)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


source = load("verification_source", "_hub-direct-verification-source.py")
lifecycle = load("verification_lifecycle", "_hub-direct-worker-lifecycle.py")


class VerificationSelectionTests(unittest.TestCase):
    def setUp(self):
        self.prefix = ".aos-direct-qualification/run/.aos-direct-upload"
        self.original = {"file": "/private/signed/source.narinfo", "relativePath": "source.narinfo",
            "sha256": "a" * 64, "byteSize": 256}
        self.bindings = {"HUB_EXTERNAL_OBJECT_CONSUMER": {},
            "HUB_EXTERNAL_STAGING_CONSUMER": {"version": 1,
                "domains": [{"staging_prefix": self.prefix}]}}

    def test_source_selector_has_no_future_original_or_version(self):
        actual = source.direct_verification_observer_selection(self.prefix, self.original)
        self.assertEqual(actual, {"version": 1, "stagingPrefix": self.prefix,
            "expectedSourceSha256": "a" * 64, "expectedSourceBytes": "256"})
        for changed in ({"byteSize": True}, {"byteSize": 65537},
                {"sha256": "sha256:" + "a" * 64}, {"providerVersion": "invented"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                source.direct_verification_observer_selection(self.prefix, {**self.original, **changed})
        for prefix in ("ordinary/objects", ".aos-direct-qualification/../.aos-direct-upload",
                ".aos-direct-qualification/run%2fother/.aos-direct-upload"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                source.direct_verification_observer_selection(prefix, self.original)

    def test_initial_optional_selection_uses_exact_installed_domain(self):
        selected = source.direct_verification_observer_selection(self.prefix, self.original)
        lifecycle.private_guest_command = lambda *args, **kwargs: self.fail("invalid selection reached guest")
        for changed in ({"stagingPrefix": ".aos-direct-qualification/other/.aos-direct-upload"},
                {"version": True}, {"expectedSourceBytes": "0256"}, {"accepted": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                lifecycle.install_direct_worker_consumers(None, "/nix/store/python/bin/python3",
                    "/private/configuration.json", self.bindings, {},
                    verification_fault_observer={**selected, **changed})

    def test_rendered_installation_remains_valid_python_with_both_consumer_domains(self):
        selected = source.direct_verification_observer_selection(self.prefix, self.original)
        commands = []
        lifecycle.private_guest_command = lambda machine, command, **kwargs: commands.append(command) or "{}"
        original = copy.deepcopy(self.bindings)
        lifecycle.install_direct_worker_consumers(None, "/nix/store/python/bin/python3",
            "/private/configuration.json", self.bindings, {}, verification_fault_observer=selected)
        program = commands[0].split("<<'INSTALL_WORKER_CONSUMERS'\n", 1)[1].rsplit("INSTALL_WORKER_CONSUMERS", 1)[0]
        ast.parse(program)
        self.assertEqual(self.bindings, original)
        self.assertIn("HUB_DIRECT_VERIFICATION_FAULT_OBSERVER", program)

    def test_failed_actual_child_retains_private_terminal_without_a_verdict(self):
        # The selected Python refuses the publisher's --json argument. This
        # exercises real failure/output custody without claiming an AOS upload.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "source.narinfo"
            original.write_bytes(b"actual controlled source\n")
            prepared = {"organizationSlug": "test", "source": {
                "surfaceRoot": str(root), "publisherHome": str(root),
                "sourceCommit": "b" * 64}, "original": {
                "file": str(original), "relativePath": original.name,
                "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                "byteSize": original.stat().st_size}}

            def guest(machine, python, body, selected, **kwargs):
                program = "import json\nselected=" + repr(selected) + "\n" + textwrap.dedent(body)
                return subprocess.run([python, "-c", program], check=True,
                    capture_output=True, text=True, timeout=10).stdout

            source.direct_guest_python = guest
            actual = source.publish_direct_verification_source(None, {
                "python": sys.executable, "aos": sys.executable,
                "workerUrl": "https://aos.andyl.org", "providerPolicyFile": "/private/policy.json",
            }, "test/read-timeout", prepared, "private-test-bearer")

            self.assertNotEqual(actual["exitCode"], 0)
            self.assertFalse(actual["timedOut"])
            self.assertIsNone(actual["remoteDrain"])
            self.assertNotIn("private-test-bearer", json.dumps(actual))
            invocation = json.loads(Path(actual["invocation"]["file"]).read_bytes())
            self.assertEqual(invocation["environment"].get("HOME"), os.environ.get("HOME"))
            self.assertIn("private-test-bearer", invocation["arguments"])
            for receipt in [actual["invocation"], *actual["outputs"].values()]:
                path = Path(receipt["file"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt["sha256"])
                self.assertEqual(str(path.stat().st_size), receipt["byteSize"])

    def test_actual_tiny_nar_selection_and_relative_url_confinement(self):
        # APR itself is outside this controlled test. Real temporary files
        # exercise the guest's selection and traversal checks after that call.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nar").mkdir()
            (root / "nar/helper.nar.xz").write_bytes(b"controlled retained NAR bytes")
            narinfo = root / "helper.narinfo"
            helper = "/nix/store/controlled-helper"
            narinfo.write_text("StorePath: " + helper + "\nURL: nar/helper.nar.xz\n")
            source.prepare_direct_signed_surface = lambda *args, **kwargs: {
                "surfaceRoot": str(root), "publisherHome": str(root), "sourceCommit": "b" * 64}
            source.read_direct_guest_file = lambda machine, python, path, maximum: Path(path).read_bytes()
            source.retain_direct_flow = lambda *args: None

            def guest(machine, python, body, selected, **kwargs):
                program = "import json\nselected=" + repr(selected) + "\n" + textwrap.dedent(body)
                return subprocess.run([python, "-c", program], check=True,
                    capture_output=True, text=True, timeout=10).stdout

            source.direct_guest_python = guest
            tools = {"python": sys.executable, "apr": "unused", "git": "unused",
                "opensshBin": "unused", "nixBin": "unused", "helperStorePath": helper,
                "workerUrl": "https://aos.andyl.org", "publicationProject": "unused"}
            actual = source.prepare_direct_verification_source(None, tools, "test")
            self.assertEqual(actual["original"]["relativePath"], "nar/helper.nar.xz")
            self.assertEqual(actual["narinfo"]["storePath"], helper)

            for url in ("nar/../outside", "nar/helper.nar.xz?token=secret", "nar/a\\b"):
                narinfo.write_text("StorePath: " + helper + "\nURL: " + url + "\n")
                with self.subTest(url=url), self.assertRaises(subprocess.CalledProcessError):
                    source.prepare_direct_verification_source(None, tools, "test")


if __name__ == "__main__":
    unittest.main()

"""Check actual shared-helper execution and controlled wire-evidence refusals.

The optional explicitly selected helper is a source-built local diagnostic. No
controlled input here is a Native TLS response or a provider qualification.
"""

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


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


prebody = load("native_prebody", "_hub-direct-prebody.py")
shared = load("shared_controls", "_hub-direct-shared-controls.py")


class PrebodyEvidenceRefusals(unittest.TestCase):
    def test_chunked_private_transfer_never_executes_or_relaxes_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            frames = []
            destination = str(Path(directory) / "copied" / "helper")

            def execute(_machine, python, program, selected, timeout=60):
                selected = {**selected, "destination": destination}
                frames.append(len(json.dumps(selected)))
                body = "import base64,json\nselected = json.loads(input())\n" + textwrap.dedent(program)
                result = subprocess.run([python, "-c", body], input=json.dumps(selected),
                    capture_output=True, text=True, timeout=timeout, check=False)
                if result.returncode:
                    raise ValueError("controlled transfer program refused")
                return result.stdout

            shared.direct_guest_python = execute
            body = b"controlled non-executable bytes\x00" * 9000
            digest = hashlib.sha256(body).hexdigest()
            receipt = shared.install_direct_control_executable(None, {"python": sys.executable}, body, digest)
            self.assertEqual(receipt["sha256"], digest)
            self.assertEqual(Path(destination).read_bytes(), body)
            self.assertEqual(Path(destination).stat().st_mode & 0o7777, 0o500)
            self.assertLess(max(frames), 256 * 1024)
            with self.assertRaises(ValueError):
                shared.install_direct_control_executable(None, {"python": sys.executable}, body, digest)

    def test_status_alone_or_missing_upload_receipt_cannot_satisfy_prebody_gate(self):
        value = {"exitCode": 0, "timedOut": False, "status": 400,
            "offeredUploadBytes": 0, "continueReceived": False, "declaredBodyBytes": 1048593}
        prebody.assert_direct_prebody_reply(value, 400)
        for field, changed in (("exitCode", 28), ("timedOut", True), ("status", None),
                ("status", 401), ("offeredUploadBytes", None), ("offeredUploadBytes", 1),
                ("continueReceived", True), ("declaredBodyBytes", 262144)):
            refused = {**value, field: changed}
            with self.assertRaises(AssertionError):
                prebody.assert_direct_prebody_reply(refused, 400)

    @unittest.skipUnless(os.environ.get("AOS_FLEET_CONTROL_HELPER"),
        "an explicit source-built shared-codec helper is required")
    def test_actual_shared_helper_held_inode_and_selected_source_fences(self):
        executable = Path(os.environ["AOS_FLEET_CONTROL_HELPER"]).resolve()
        with executable.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        revision = os.environ["AOS_FLEET_CONTROL_CODEC_REVISION"]
        receipts = []
        shared._closed_review_json = json.loads
        shared.retain_direct_flow = lambda name, value: receipts.append((name, copy.deepcopy(value)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected_requests = {}

            def install(_machine, _python, requested, body):
                path = root / Path(requested).name
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(body)
                selected_requests[requested] = str(path)

            def execute(_machine, python, program, selected, timeout=60):
                selected = {**selected, "request": selected_requests[selected["request"]]}
                body = "import json\nselected = json.loads(input())\n" + textwrap.dedent(program)
                result = subprocess.run([python, "-c", body], input=json.dumps(selected),
                    capture_output=True, text=True, timeout=timeout, check=False)
                if result.returncode:
                    raise ValueError("controlled held-inode program refused")
                return result.stdout

            shared.install_direct_guest_file = install
            shared.direct_guest_python = execute
            key = root / "key"
            body = root / "body"
            key.write_bytes(bytes([17]) * 32)
            body.write_bytes(b"controlled payload")
            key.chmod(0o600)
            body.chmod(0o600)
            helper = {"executable": str(executable), "executableSha256": digest,
                "codecRevision": revision}
            selection = {"kind": "ingress_prepare", "key_file": str(key),
                "deployment_id": "controlled-deployment", "authority": "controlled.test",
                "method": "PUT", "path_and_query": "/aos.hub.v1.PublishService/UploadObject/a/b",
                "body_file": str(body), "signed_phase": "preflight", "header_phase": "admit",
                "output_directory": str(root / "signed")}
            result = shared.run_direct_shared_control(None, {"python": sys.executable},
                helper, selection, "controlled-positive")
            self.assertEqual(result["codecRevision"], revision)
            self.assertEqual(receipts[-1][1]["executableSha256"], digest)
            self.assertEqual(receipts[-1][1]["exitCode"], 0)
            self.assertNotIn(str(key), receipts[-1][1]["stdout"])

            changed = {**selection, "output_directory": str(root / "never-executed")}
            with self.assertRaises(ValueError):
                shared.run_direct_shared_control(None, {"python": sys.executable},
                    {**helper, "executableSha256": "f" * 64}, changed, "controlled-wrong-hash")
            self.assertFalse((root / "never-executed").exists())
            with self.assertRaises(ValueError):
                shared.run_direct_shared_control(None, {"python": sys.executable},
                    {**helper, "codecRevision": "f" * 40},
                    {**selection, "output_directory": str(root / "wrong-source")}, "controlled-wrong-source")
            self.assertEqual(receipts[-1][1]["exitCode"], 0)


if __name__ == "__main__":
    unittest.main()

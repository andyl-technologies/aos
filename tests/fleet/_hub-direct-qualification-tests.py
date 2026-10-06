"""Exercise bounded invocation retention with the actual emitted guest reader.

Only guest transport is local. The tests use disposable private files and never
invoke a Worker, provider, qualification control, or operator credential.
"""

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


path = Path(__file__).with_name("_hub-direct-qualification.py")
specification = importlib.util.spec_from_file_location("qualification", path)
qualification = importlib.util.module_from_spec(specification)
specification.loader.exec_module(qualification)


class InvocationRetention(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.guest = self.root / "guest"
        self.host = self.root / "host"
        self.guest.mkdir(mode=0o700)
        self.host.mkdir(mode=0o700)
        self.run_id = "a" * 64
        self.guest_path = "/var/lib/hybrid-worker/operator/prequalification-" + self.run_id + "-recovered"
        self.receipt = {"runId": self.run_id, "guestDirectory": self.guest_path,
                        "exitCode": 1, "timedOut": False}
        self.requests = []
        qualification.direct_guest_python = self.read_guest

    def write(self, name, body):
        path = self.guest / name
        path.write_bytes(body)
        path.chmod(0o600)
        self.receipt[name.removesuffix(".log") + "Sha256"] = hashlib.sha256(body).hexdigest()

    def read_guest(self, _worker, python, body, selected, timeout=60):
        # Substitute only the transport's test directory. The emitted reader,
        # file allowlist, custody checks and byte bounds execute unchanged.
        self.assertEqual(selected["root"], self.guest_path)
        self.requests.append(selected["name"])
        inputs = {**selected, "root": str(self.guest)}
        program = "import json\nselected = json.loads(input())\n" + textwrap.dedent(body)
        result = subprocess.run([python, "-B", "-c", program], input=json.dumps(inputs),
                                text=True, capture_output=True, timeout=timeout, check=False)
        if result.returncode != 0:
            raise ValueError("controlled guest reader refused")
        return result.stdout

    def retain(self):
        return qualification.retain_direct_qualification_output(
            None, sys.executable, self.guest_path, str(self.host), self.receipt)

    def test_exact_binary_outputs_survive_without_public_permissions(self):
        self.write("stdout.log", b"\x00\xff" + b"x" * 65534)
        self.write("stderr.log", b"controlled child refusal\n")

        result = self.retain()

        self.assertEqual(self.requests, ["stdout.log", "stderr.log"])
        self.assertEqual([item["state"] for item in result["files"]], ["retained", "retained"])
        for item in result["files"]:
            retained = self.host / item["name"]
            self.assertEqual(retained.read_bytes(), (self.guest / item["name"]).read_bytes())
            self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            self.assertEqual(retained.stat().st_nlink, 1)
            self.assertEqual(item["byteSize"], retained.stat().st_size)

    def test_oversized_stderr_keeps_stdout_and_explicit_unknown(self):
        self.write("stdout.log", b"retained result\n")
        self.write("stderr.log", b"x" * 65537)

        result = self.retain()

        self.assertEqual(result["files"][0]["state"], "retained")
        self.assertEqual(result["files"][1], {"name": "stderr.log", "state": "refused_or_unknown"})
        self.assertFalse((self.host / "stderr.log").exists())

    def test_missing_stderr_keeps_the_other_stream(self):
        self.write("stdout.log", b"complete stream")
        self.receipt["stderrSha256"] = "0" * 64

        result = self.retain()

        self.assertEqual([item["state"] for item in result["files"]], ["retained", "refused_or_unknown"])

    def test_changed_hash_symlink_and_shared_file_are_refused(self):
        self.write("stdout.log", b"changed stream")
        self.write("stderr.log", b"same private stream")
        self.receipt["stdoutSha256"] = "0" * 64
        os.link(self.guest / "stderr.log", self.guest / "alias")
        result = self.retain()
        self.assertTrue(all(item["state"] == "refused_or_unknown" for item in result["files"]))
        self.assertEqual(list(self.host.iterdir()), [])

        (self.guest / "stderr.log").unlink()
        (self.guest / "stderr.log").symlink_to(self.guest / "alias")
        result = self.retain()
        self.assertTrue(all(item["state"] == "refused_or_unknown" for item in result["files"]))
        self.assertEqual(list(self.host.iterdir()), [])

    def test_existing_host_output_is_not_overwritten(self):
        self.write("stdout.log", b"new output")
        self.write("stderr.log", b"new error")
        existing = self.host / "stdout.log"
        existing.write_bytes(b"prior retained original")
        existing.chmod(0o600)

        result = self.retain()

        self.assertEqual(result["files"][0]["state"], "refused_or_unknown")
        self.assertEqual(existing.read_bytes(), b"prior retained original")
        self.assertEqual(result["files"][1]["state"], "retained")

    def test_foreign_directory_and_public_source_are_refused(self):
        self.write("stdout.log", b"private output")
        self.write("stderr.log", b"public output")
        (self.guest / "stderr.log").chmod(0o644)
        result = self.retain()
        self.assertEqual([item["state"] for item in result["files"]], ["retained", "refused_or_unknown"])

        self.requests.clear()
        with self.assertRaisesRegex(ValueError, "directory differs"):
            qualification.retain_direct_qualification_output(
                None, sys.executable, "/unrelated/output", str(self.host), self.receipt)
        self.assertEqual(self.requests, [])

    def test_failed_invocation_retains_streams_before_raising(self):
        self.write("stdout.log", b"failed invocation output")
        self.write("stderr.log", b"failed invocation error")
        actual_reader = self.read_guest

        def guest(_worker, python, body, selected, timeout=60):
            if "arguments" in selected:
                return json.dumps({**self.receipt, "phase": "requeue"})
            return actual_reader(_worker, python, body, selected, timeout)

        qualification.direct_guest_python = guest
        qualification.retain_direct_qualification_files = lambda *args: {
            "directory": str(self.host), "files": []}
        with self.assertRaisesRegex(RuntimeError, "qualification recovery invocation failed"):
            qualification.observe_direct_prequalification_phase(
                None, {"python": sys.executable, "node": "controlled-node",
                       "qualificationDriver": "controlled-driver"},
                "https://fixture.test", "unused-control", "unused-identity",
                self.run_id, "requeue", "recovered")

        report = json.loads((self.host / "fleet-invocation.json").read_bytes())
        self.assertEqual(report["process"]["exitCode"], 1)
        self.assertEqual([item["state"] for item in report["invocationOutput"]["files"]],
                         ["retained", "retained"])
        self.assertEqual((self.host / "stderr.log").read_bytes(), b"failed invocation error")


if __name__ == "__main__":
    unittest.main()

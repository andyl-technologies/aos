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
from unittest.mock import patch


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
            None, sys.executable, self.guest_path, str(self.host), self.receipt, retention_label="recovered")

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
                None, sys.executable, "/unrelated/output", str(self.host), self.receipt, retention_label="recovered")
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
        self.host.rmdir()
        self.host = self.root / "external-direct-prequalification" / (self.run_id + "-recovered")
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.object(qualification, "retain_direct_qualification_files", lambda *args, **kwargs: {
                    "directory": str(self.host), "files": []}):
                with self.assertRaisesRegex(RuntimeError, "qualification recovery invocation failed"):
                    qualification.observe_direct_prequalification_phase(
                        None, {"python": sys.executable, "node": "controlled-node",
                               "qualificationDriver": "controlled-driver"},
                        "https://fixture.test", "unused-control", "unused-identity",
                        self.run_id, "requeue", "recovered")
        finally:
            os.chdir(previous)

        report = json.loads((self.host / "fleet-invocation.json").read_bytes())
        self.assertEqual(report["process"]["exitCode"], 1)
        self.assertEqual([item["state"] for item in report["invocationOutput"]["files"]],
                         ["retained", "retained"])
        self.assertEqual((self.host / "stderr.log").read_bytes(), b"failed invocation error")


class BatchedObservationRetention(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.previous_directory = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous_directory)
        self.guest = self.root / "evidence"
        self.guest.mkdir(mode=0o700)
        self.run_id = "b" * 64
        self.calls = []
        self.before_export = None
        self.after_export = None
        self.transform_export = None
        self.patch = patch.object(qualification, "direct_guest_python", self.transport, create=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write(self, name, body):
        path = self.guest / name
        path.write_bytes(body)
        path.chmod(0o600)
        return {"name": name, "sha256": hashlib.sha256(body).hexdigest()}

    def manifest(self, files):
        self.write("file-manifest.json", json.dumps({"version": 1, "runId": self.run_id,
            "files": list(reversed(files))}).encode())

    def transport(self, _worker, python, body, selected, timeout=60):
        inputs = {**selected, "directory": str(self.guest)}
        self.calls.append([item["name"] for item in selected["files"]] if "files" in selected else "inventory")
        if "files" in selected and self.before_export:
            self.before_export(selected)
        program = "import json\nselected = json.loads(input())\n" + textwrap.dedent(body)
        result = subprocess.run([python, "-B", "-c", program], input=json.dumps(inputs),
            text=True, capture_output=True, timeout=timeout, check=False)
        if result.returncode != 0:
            raise ValueError("controlled emitted guest reader refused")
        if "files" in selected and self.after_export:
            self.after_export(selected)
        if "files" in selected and self.transform_export:
            return self.transform_export(selected, result.stdout)
        return result.stdout

    def retain(self, **kwargs):
        return qualification.retain_direct_qualification_files(
            None, sys.executable, "/controlled/evidence", self.run_id, **kwargs)

    def test_count_boundary_retains_all_actual_bytes_and_full_manifest(self):
        files = [self.write(f"{index:05d}.json", json.dumps({"controlled": index}).encode())
                 for index in range(65)]
        self.manifest(files)
        result = self.retain()
        self.assertEqual([len(batch) for batch in self.calls if isinstance(batch, list)], [1, 64, 1])
        self.assertEqual(len(result["files"]), 65)
        self.assertTrue(result["driverManifestPresent"])
        self.assertEqual(self.calls.count("inventory"), 2)
        for item in result["files"]:
            output = Path(result["directory"]) / item["name"]
            self.assertEqual(output.read_bytes(), (self.guest / item["name"]).read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.stat().st_nlink, 1)

    def test_decoded_byte_boundary_does_not_split_or_omit_large_files(self):
        files = [self.write(f"{index:05d}.json", bytes([65 + index]) * 4194304) for index in range(3)]
        self.manifest(files)
        result = self.retain()
        self.assertEqual([len(batch) for batch in self.calls if isinstance(batch, list)], [1, 2, 1])
        self.assertEqual(sum(item["byteSize"] for item in result["files"]), 3 * 4194304)

    def test_missing_manifest_is_observation_only_not_driver_completion(self):
        self.write("incomplete-run-outcome.json", b'{"state":"incomplete"}')
        result = self.retain()
        self.assertFalse(result["driverManifestPresent"])
        self.assertIsNone(result["manifestSha256"])
        self.assertFalse((Path(result["directory"]) / "file-manifest.json").exists())

    def test_manifest_missing_extra_or_wrong_hash_cannot_authorize_export(self):
        file = self.write("00001.json", b"controlled observation")
        for name, entries in (("missing", []), ("extra", [file, {"name": "absent.json", "sha256": "0" * 64}]),
                              ("hash", [{**file, "sha256": "0" * 64}])):
            with self.subTest(case=name):
                self.manifest(entries)
                with self.assertRaisesRegex(ValueError, "manifest|committed"):
                    self.retain()
                output = qualification.qualification_retention_directory(self.run_id)
                self.assertEqual(list(output.iterdir()), [])
                output.rmdir()

    def test_content_change_after_inventory_refuses_export(self):
        file = self.write("00001.json", b"original")
        self.manifest([file])
        self.before_export = lambda selected: self.write("00001.json", b"changed!") if selected["files"][0]["name"] == "00001.json" else None
        with self.assertRaisesRegex(ValueError, "guest reader refused"):
            self.retain()
        self.assertFalse((qualification.qualification_retention_directory(self.run_id) / "00001.json").exists())

    def test_transport_byte_tampering_is_rejected_before_host_creation(self):
        file = self.write("00001.json", b"actual bytes")
        self.manifest([file])

        def tamper(selected, encoded):
            if selected["files"][0]["name"] == "file-manifest.json":
                return encoded
            observed = json.loads(encoded)
            observed["files"][0]["body"] = "Zm9yZWlnbiBieXRlcw=="
            return json.dumps(observed)

        self.transform_export = tamper
        with self.assertRaisesRegex(ValueError, "exported bytes differ"):
            self.retain()
        self.assertFalse((qualification.qualification_retention_directory(self.run_id) / "00001.json").exists())

    def test_change_after_copy_is_detected_by_full_final_inventory(self):
        file = self.write("00001.json", b"actual original")
        self.manifest([file])
        self.after_export = lambda selected: self.write("new-file.json", b"added") if selected["files"][0]["name"] == "00001.json" else None
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            self.retain()
        self.assertEqual((qualification.qualification_retention_directory(self.run_id) / "00001.json").read_bytes(), b"actual original")

    def test_symlink_hardlink_public_file_and_directory_are_refused(self):
        file = self.write("00001.json", b"selected")
        self.manifest([file])
        for case in ("symlink", "hardlink", "public", "directory"):
            with self.subTest(case=case):
                path = self.guest / file["name"]
                if case == "symlink":
                    path.unlink()
                    path.symlink_to(self.guest / "file-manifest.json")
                elif case == "hardlink":
                    path.unlink()
                    os.link(self.guest / "file-manifest.json", path)
                elif case == "public":
                    path.unlink()
                    path.write_bytes(b"selected")
                    path.chmod(0o644)
                else:
                    path.chmod(0o600)
                    self.guest.chmod(0o755)
                with self.assertRaisesRegex(ValueError, "guest reader refused"):
                    self.retain()
                output = qualification.qualification_retention_directory(self.run_id)
                self.assertEqual(list(output.iterdir()), [])
                output.rmdir()

    def test_interrupted_export_preserves_early_actual_receipt_and_first_batch(self):
        files = [self.write(f"{index:05d}.json", b"controlled observation") for index in range(65)]
        self.manifest(files)
        receipt = {"runId": self.run_id, "exitCode": None, "timedOut": True,
            "guestDirectory": "/controlled/original"}
        destination = qualification.retain_direct_qualification_process(receipt)
        def interrupt(selected):
            if selected["files"][0]["name"] == "00064.json":
                raise TimeoutError("controlled interrupted transfer")
        self.before_export = interrupt
        with self.assertRaises(TimeoutError):
            self.retain(host_directory=destination)
        self.assertEqual(json.loads((destination / "fleet-process.json").read_bytes()), receipt)
        self.assertEqual(len(list(destination.glob("[0-9]*.json"))), 64)
        self.assertFalse((destination / "file-manifest.json").exists())
        observed = json.loads((destination / "observed-file-inventory.json").read_bytes())
        self.assertEqual(len(observed["files"]), 66)
        self.assertIn("not a driver completion claim", observed["scope"])

    def test_existing_host_file_is_never_overwritten(self):
        file = self.write("00001.json", b"new bytes")
        self.manifest([file])
        destination = qualification.retain_direct_qualification_process({"runId": self.run_id, "exitCode": 1})
        existing = destination / "00001.json"
        existing.write_bytes(b"previous evidence")
        existing.chmod(0o600)
        with self.assertRaises(FileExistsError):
            self.retain(host_directory=destination)
        self.assertEqual(existing.read_bytes(), b"previous evidence")


class EarlyProcessReceipt(unittest.TestCase):
    def test_nonzero_and_timeout_are_durable_before_interrupted_retention(self):
        for timed_out, exit_code in ((False, 3), (True, None)):
            with self.subTest(timedOut=timed_out), tempfile.TemporaryDirectory() as directory:
                previous = Path.cwd()
                os.chdir(directory)
                run_id = "c" * 64
                receipt = {"runId": run_id, "phase": "status", "exitCode": exit_code,
                    "timedOut": timed_out, "guestDirectory": "/var/lib/hybrid-worker/operator/prequalification-" + run_id + "-current"}
                output_called = []
                def outputs(*args, **kwargs):
                    root = Path(args[3])
                    self.assertEqual(json.loads((root / "fleet-process.json").read_bytes()), receipt)
                    output_called.append(True)
                    return {"files": [{"name": "stdout.log", "state": "retained"},
                                      {"name": "stderr.log", "state": "refused_or_unknown"}]}
                try:
                    with patch.object(qualification, "direct_guest_python", lambda *a, **k: json.dumps(receipt), create=True), \
                            patch.object(qualification, "retain_direct_qualification_output", outputs), \
                            patch.object(qualification, "retain_direct_qualification_files", side_effect=TimeoutError("controlled export interruption")):
                        with self.assertRaises(TimeoutError):
                            qualification.observe_direct_prequalification_phase(None,
                                {"python": sys.executable, "node": "unused", "qualificationDriver": "unused"},
                                "https://fixture.test", "unused", "unused", run_id, "status", "current")
                    self.assertEqual(output_called, [True])
                    root = qualification.qualification_retention_directory(run_id, "current")
                    self.assertEqual(json.loads((root / "fleet-process.json").read_bytes()), receipt)
                    self.assertFalse((root / "fleet-invocation.json").exists())
                    streams = json.loads((root / "fleet-invocation-output.json").read_bytes())
                    self.assertEqual(streams["files"][1]["state"], "refused_or_unknown")
                finally:
                    os.chdir(previous)

    def test_ordinary_preflight_retains_outputs_before_batch_without_source_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            run_id = "d" * 64
            root = "/var/lib/hybrid-worker/external-oci/" + "e" * 32 + "/operator"
            receipt = {"runId": run_id, "exitCode": 1, "timedOut": False,
                "guestDirectory": root + "/prequalification-" + run_id}
            calls = []
            guest = Path(directory) / "child-output"
            guest.mkdir(mode=0o700)
            for name, body in (("stdout.log", b"actual bounded child output"),
                               ("stderr.log", b"controlled child refusal")):
                path = guest / name
                path.write_bytes(body)
                path.chmod(0o600)
                receipt[name.removesuffix(".log") + "Sha256"] = hashlib.sha256(body).hexdigest()

            def read_output(_worker, python, body, selected, timeout=60):
                self.assertEqual(selected["root"], receipt["guestDirectory"])
                destination = qualification.qualification_retention_directory(run_id)
                self.assertTrue((destination / "fleet-process.json").exists())
                calls.append(selected["name"])
                program = "import json\nselected = json.loads(input())\n" + textwrap.dedent(body)
                result = subprocess.run([python, "-B", "-c", program],
                    input=json.dumps({**selected, "root": str(guest)}), text=True,
                    capture_output=True, timeout=timeout, check=False)
                if result.returncode:
                    raise ValueError("controlled output reader refused")
                return result.stdout
            def retain(*args, **kwargs):
                destination = qualification.qualification_retention_directory(run_id)
                observed = json.loads((destination / "worker-runtime-observation.json").read_bytes())
                self.assertEqual(observed["state"], "unknown")
                self.assertEqual(observed["category"], "worker_owner_not_selected")
                self.assertIsNone(observed["owner"])
                self.assertFalse((destination / "worker-runtime.log").exists())
                calls.append("inventory")
                raise TimeoutError("controlled export interruption")
            try:
                with patch.object(qualification.os, "urandom", return_value=bytes.fromhex(run_id)), \
                        patch.object(qualification, "private_guest_command", return_value=json.dumps(receipt), create=True), \
                        patch.object(qualification, "direct_guest_python", read_output, create=True), \
                        patch.object(qualification, "retain_direct_qualification_files", retain):
                    with self.assertRaises(TimeoutError):
                        qualification.run_direct_prequalification(None, sys.executable, "unused-node", "unused-driver",
                            "https://fixture.test", "unused-key", "unused-identity", {},
                            [{"file": "/controlled/bulk", "metadata": False}] * 3,
                            [{"file": "/controlled/metadata", "metadata": True}] * 4, operator_root=root)
                self.assertEqual(calls, ["stdout.log", "stderr.log", "inventory"])
                destination = qualification.qualification_retention_directory(run_id)
                self.assertEqual(json.loads((destination / "fleet-process.json").read_bytes()), receipt)
                self.assertEqual((destination / "stderr.log").read_bytes(), b"controlled child refusal")
                self.assertEqual((destination / "stdout.log").read_bytes(), b"actual bounded child output")
            finally:
                os.chdir(previous)


class WorkerLogRetention(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.guest = self.root / "guest"
        self.host = self.root / "host"
        self.guest.mkdir(mode=0o700)
        self.host.mkdir(mode=0o700)
        self.log = self.guest / "observed.log"
        self.log.write_bytes(b"before the invocation\n")
        self.log.chmod(0o600)
        output = self.log.open("ab")
        self.child = subprocess.Popen([sys.executable, "-B", "-c",
            "import sys\nfor line in sys.stdin:\n print(line.strip(), flush=True)"],
            stdin=subprocess.PIPE, stdout=output, stderr=output)
        output.close()
        self.addCleanup(self.stop_child)
        proc = Path("/proc") / str(self.child.pid)
        fields = (proc / "stat").read_text().rpartition(") ")[2].split()
        self.owner = {"pid": self.child.pid, "ownerUid": proc.stat().st_uid,
            "startTicks": fields[19], "logFile": "/var/lib/hybrid-worker/observed.log",
            "configurationSha256": "a" * 64}
        self.requests = []
        self.previous_reader = getattr(qualification, "direct_guest_python", None)
        qualification.direct_guest_python = self.read_guest
        self.addCleanup(self.restore_reader)

    def restore_reader(self):
        qualification.direct_guest_python = self.previous_reader

    def stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(timeout=5)
        self.child.stdin.close()

    def read_guest(self, _worker, python, body, selected, timeout=30):
        self.requests.append({"offset": selected["offset"], "length": selected["length"]})
        inputs = {**selected, "root": str(self.guest)}
        program = "import json\nselected = json.loads(input())\n" + textwrap.dedent(body)
        result = subprocess.run([python, "-B", "-c", program], input=json.dumps(inputs),
            text=True, capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            raise ValueError("controlled transport failure")
        return result.stdout

    def observe(self, **fields):
        return qualification.observe_direct_qualification_worker_log(None, sys.executable,
            self.owner, "/var/lib/hybrid-worker/operator", **fields)

    def retain(self, before):
        return qualification.retain_direct_qualification_worker_log(None, sys.executable,
            self.owner, "/var/lib/hybrid-worker/operator", before, self.host, "b" * 64)

    def test_actual_owned_child_interval_survives_before_failure(self):
        import time
        before = self.observe()
        self.child.stdin.write(b"direct_qualification_attempt synthetic fixed-phase fixture\n")
        self.child.stdin.flush()
        deadline = time.monotonic() + 3
        while self.log.stat().st_size == before["position"]["byteSize"]:
            if time.monotonic() >= deadline:
                self.fail("actual child produced no log")
            time.sleep(0.01)

        retained = self.retain(before)

        body = (self.host / "worker-runtime.log").read_bytes()
        self.assertEqual(body, b"direct_qualification_attempt synthetic fixed-phase fixture\n")
        self.assertEqual(retained["state"], "retained")
        self.assertEqual(retained["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(retained["capturedBytes"], len(body))
        self.assertEqual((self.host / "worker-runtime.log").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.host / "worker-runtime-observation.json").read_bytes()), retained)
        self.assertTrue(all(row["length"] is None or row["length"] <= 1024 * 1024
                            for row in self.requests))

    def test_custody_rotation_and_lifetime_fail_without_reading_foreign_body(self):
        before = self.observe()
        selected_path = self.owner["logFile"]
        self.owner["logFile"] = "/foreign/observed.log"
        count = len(self.requests)
        self.assertEqual(self.observe()["category"], "worker_owner_shape_refused")
        self.assertEqual(len(self.requests), count)
        self.owner["logFile"] = selected_path
        self.owner["startTicks"] = str(int(self.owner["startTicks"]) + 1)
        self.assertEqual(self.observe()["category"], "worker_lifetime_changed")
        self.owner["startTicks"] = (Path("/proc") / str(self.child.pid) / "stat").read_text().rpartition(") ")[2].split()[19]
        self.log.chmod(0o644)
        self.assertNotIn("body", self.observe())
        self.assertEqual(self.observe()["category"], "worker_log_custody_refused")
        self.log.chmod(0o600)
        self.log.rename(self.guest / "prior.log")
        self.log.write_bytes(b"foreign private bytes never retained")
        self.log.chmod(0o600)
        self.assertEqual(self.observe(before=before["position"])["category"], "worker_log_identity_changed")
        self.stop_child()
        self.assertEqual(self.observe()["category"], "worker_lifetime_missing")

    def test_bounded_interval_refuses_without_creating_or_overwriting_log(self):
        before = self.observe()
        with self.log.open("ab") as output:
            output.truncate(before["position"]["byteSize"] + 16 * 1024 * 1024 + 1)
        retained = self.retain(before)
        self.assertEqual(retained["category"], "worker_log_bound_refused")
        self.assertFalse((self.host / "worker-runtime.log").exists())
        self.assertTrue((self.host / "worker-runtime-observation.json").exists())

    def test_transport_unknown_and_destination_collision_never_replace_original_data(self):
        before = self.observe()
        target = self.host / "worker-runtime.log"
        target.write_bytes(b"existing retained bytes")
        target.chmod(0o600)
        retained = self.retain(before)
        self.assertEqual(retained["state"], "unknown")
        self.assertEqual(target.read_bytes(), b"existing retained bytes")
        self.assertEqual(retained["category"], "worker_log_retention_unavailable")

        def failed(*unused, **unused_keywords):
            raise RuntimeError("synthetic private transport text must not escape")

        qualification.direct_guest_python = failed
        unknown = self.observe()
        self.assertEqual(unknown, {"state": "unknown", "category": "worker_log_observation_unavailable"})
        self.assertNotIn("synthetic private", json.dumps(unknown))


if __name__ == "__main__":
    unittest.main()

"""Controlled local custody and socket tests; no Worker, VM or R2 SDK effects."""

import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest


spec = importlib.util.spec_from_file_location(
    "oci_anchor_fixture", Path(__file__).with_name("_hub-oci-sdk-anchor.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class AnchorFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aos-oci-anchor-controlled-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.executable = Path(sys.executable).resolve()
        self.pin = fixture.namespace_reader.process_identity(os.getpid(), self.executable)
        self.namespace = {field: "a" * 64 for field in fixture.namespace_reader.FIELDS}
        self.namespace.update(version=1, observationScope="oci_sdk_emulator_namespace_readback",
            namespaceId="oci-sdk-qualification-" + "b" * 32, runnerPid=os.getpid(),
            runnerStartTicks=self.pin["startTicks"], observedAt="2026-10-01T00:00:00.000Z")
        self.namespace_file = self.root / "namespace.json"
        fixture.persist(self.namespace_file, fixture.json_bytes(self.namespace))
        self.original_directory = self.root / "original"

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self):
        result = fixture.prepare(self.namespace_file, self.original_directory)
        original = fixture.namespace_reader.closed_json(
            (self.original_directory / "original.json").read_bytes())
        return result, original

    def positive(self, original):
        request = json.loads((self.original_directory / "request.json").read_bytes())
        return {"version": 1, "status": "observed", "runId": original["runId"],
            "originalSha256": request["originalSha256"],
            "namespaceObservationSha256": original["namespaceObservationSha256"],
            "completedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sdkInvocations": {"put": 1, "get": 1}, "anchor": {"object": {
                "key": ".aos-oci-sdk-qualification/" + original["runId"] + "/anchor",
                "provider_version": "c" * 32, "etag": '"' + "d" * 32 + '"',
                "size": int(original["payloadByteSize"])}, "sha256": original["payloadSha256"]}}

    def run_peer(self, response):
        socket_file = self.root / "runner.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_file))
        socket_file.chmod(0o600)
        listener.listen(1)
        requests = []

        def serve():
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    body = bytearray()
                    while block := connection.recv(4096):
                        body.extend(block)
                    requests.append(bytes(body))
                    connection.sendall(fixture.json_bytes(response))

        thread = threading.Thread(target=serve)
        thread.start()
        return socket_file, thread, requests

    def test_prepare_is_bounded_random_create_new_and_explicitly_retained(self):
        result, original = self.prepare()
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(int(original["expiresAt"]) - int(original["issuedAt"]), 30)
        payload = base64.b64decode(original["payloadBase64"], validate=True)
        self.assertEqual(len(payload), 256)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), original["payloadSha256"])
        self.assertEqual(fixture.validated_original(fixture.json_bytes(original))[0], original)
        self.assertEqual(set(path.name for path in self.original_directory.iterdir()),
            {"original.json", "request.json"})
        self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in self.original_directory.iterdir()))
        with self.assertRaises(FileExistsError):
            fixture.prepare(self.namespace_file, self.original_directory)

    def test_non_dedicated_scope_duplicate_fields_and_private_file_substitution_refuse(self):
        for field, value in (("namespaceId", "ordinary-registry"), ("observationScope", "hosted")):
            observation = dict(self.namespace)
            observation[field] = value
            self.namespace_file.write_bytes(fixture.json_bytes(observation))
            with self.assertRaises(ValueError):
                fixture.prepare(self.namespace_file, self.original_directory)
            self.assertFalse(self.original_directory.exists())
        self.namespace_file.write_bytes(fixture.json_bytes(self.namespace))
        self.namespace_file.chmod(0o644)
        with self.assertRaises(ValueError):
            fixture.prepare(self.namespace_file, self.original_directory)
        self.namespace_file.chmod(0o600)
        alias = self.root / "alias"
        alias.symlink_to(self.namespace_file)
        with self.assertRaises(OSError):
            fixture.prepare(alias, self.original_directory)
        with self.assertRaises(ValueError):
            fixture.namespace_reader.closed_json(b'{"version":1,"version":1}')

    def test_original_tamper_types_ttl_and_embedded_digest_refuse(self):
        _, original = self.prepare()
        for change in ({"version": True}, {"extra": 1}, {"runId": "bad"},
                {"issuedAt": int(original["issuedAt"])}, {"payloadByteSize": "0256"},
                {"expiresAt": str(int(original["issuedAt"]) + 31)},
                {"payloadSha256": "0" * 64}, {"namespaceObservationSha256": "0" * 64},
                {"payloadBase64": "!!!"}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                fixture.validated_original(fixture.json_bytes({**original, **change}))
        original_file = self.original_directory / "original.json"
        original_file.write_bytes(fixture.json_bytes({**original, "runId": "f" * 32}))
        with self.assertRaises(ValueError):
            fixture.dispatch(self.original_directory, self.root / "not-a-socket", self.executable)
        self.assertFalse((self.original_directory / "dispatch-intent.json").exists())

    def test_exact_local_peer_receipt_is_retained_and_second_dispatch_cannot_send(self):
        _, original = self.prepare()
        response = self.positive(original)
        socket_file, thread, requests = self.run_peer(response)
        try:
            result = fixture.dispatch(self.original_directory, socket_file, self.executable)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(json.loads((self.original_directory / "anchor.json").read_bytes()), response["anchor"])
            self.assertEqual((self.original_directory / "response.json").read_bytes(), fixture.json_bytes(response))
            self.assertEqual(requests, [(self.original_directory / "request.json").read_bytes()])
            with self.assertRaises(FileExistsError):
                fixture.dispatch(self.original_directory, socket_file, self.executable)
            self.assertEqual(len(requests), 1)
        finally:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_unknown_or_substituted_reply_preserves_intent_and_never_creates_anchor(self):
        for mode in ("unknown", "version", "body-digest", "scope", "expiry"):
            with self.subTest(mode=mode):
                if self.original_directory.exists():
                    self.tearDown()
                    self.setUp()
                _, original = self.prepare()
                response = self.positive(original)
                if mode == "unknown":
                    response = {"status": "unknown", "runId": original["runId"],
                        "originalSha256": response["originalSha256"]}
                elif mode == "version":
                    response["anchor"]["object"]["provider_version"] = ""
                elif mode == "body-digest":
                    response["anchor"]["sha256"] = "0" * 64
                elif mode == "scope":
                    response["sdkInvocations"]["put"] = 2
                else:
                    response["completedAt"] = datetime.fromtimestamp(int(original["expiresAt"]),
                        timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                socket_file, thread, requests = self.run_peer(response)
                try:
                    with self.assertRaises(ValueError):
                        fixture.dispatch(self.original_directory, socket_file, self.executable)
                    self.assertTrue((self.original_directory / "response.json").is_file())
                    self.assertTrue((self.original_directory / "dispatch-intent.json").is_file())
                    self.assertFalse((self.original_directory / "anchor.json").exists())
                    with self.assertRaises(FileExistsError):
                        fixture.dispatch(self.original_directory, socket_file, self.executable)
                    self.assertEqual(len(requests), 1)
                finally:
                    thread.join(timeout=3)
                    self.assertFalse(thread.is_alive())

    def test_actual_cli_prepare_status_and_safe_error_output_have_no_effect_phase(self):
        command = [sys.executable, str(Path(fixture.__file__))]
        result = subprocess.run(command + ["prepare", "--namespace-observation-file", str(self.namespace_file),
            "--output-directory", str(self.original_directory)], capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout)["status"], "prepared")
        self.assertEqual(result.stderr, b"")
        result = subprocess.run(command + ["status", "--original-directory", str(self.original_directory)],
            capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout)["scope"], "retained_files_only")
        self.assertEqual(set(json.loads(result.stdout)["files"]), {"original.json", "request.json"})
        self.assertEqual(result.stderr, b"")
        failed = subprocess.run(command + ["prepare", "--namespace-observation-file", str(self.namespace_file),
            "--output-directory", str(self.original_directory)], capture_output=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(failed.stdout, b"")
        self.assertNotIn(str(self.root).encode(), failed.stderr)


if __name__ == "__main__":
    unittest.main()

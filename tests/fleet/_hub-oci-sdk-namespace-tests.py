"""Controlled readback, custody and real process tests; no R2 SDK effects."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import socket
import threading
import unittest


spec = importlib.util.spec_from_file_location("namespace_observer",
    Path(__file__).with_name("_hub-oci-sdk-namespace.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def fixture():
    source = "/nix/store/" + "0" * 32 + "-controlled-source"
    digest = hashlib.sha256(source.encode()).hexdigest()
    configuration = {"r2Buckets": {"REGISTRY_BUCKET": "controlled-namespace"},
        "name": "controlled-worker", "resourcePersistencePath": "/controlled/private-state",
        "scriptPath": "/controlled/shim.mjs"}
    selected = {"sourceStorePath": source, "configurationBytes": json.dumps(configuration).encode(),
                "shimFile": configuration["scriptPath"]}
    identity = {"sourceDigest": digest, "scriptVersion": "emulated-" + digest}
    runner = {"pid": 42, "startTicks": "123", "parentPid": 1}
    workerd = {"pid": 43, "startTicks": "124", "parentPid": 42}
    actual = {name: "a" * 64 for name in observer.FIELDS if name.endswith("Sha256")}
    actual.update(version=1, observationScope="oci_sdk_emulator_namespace_readback",
        observedAt="2026-10-01T00:00:00.000Z", runnerPid=42, runnerStartTicks="123",
        miniflareVersion="5.20260801.0-alpha", wasmByteSize="1024", sourceStorePath=source,
        buildDerivedSourceDigest=digest, buildDerivedScriptVersion="emulated-" + digest,
        workerName="controlled-worker", bindingName="REGISTRY_BUCKET", namespaceId="controlled-namespace",
        namespaceUniqueKey="miniflare-R2BucketObject", namespaceObjectId="b" * 64,
        persistenceRoot="/controlled/private-state/r2", workerdPid=43, workerdStartTicks="124")
    hashes = {name: value for name, value in actual.items() if name.endswith("Sha256")}
    hashes["wasmByteSize"] = "1024"
    return actual, selected, identity, runner, workerd, hashes


class NamespaceObservationTests(unittest.TestCase):
    def test_exact_controlled_closed_join(self):
        values = fixture()
        self.assertEqual(observer.validate_readback(*values), values[0])
        self.assertEqual(set(values[0]), observer.FIELDS)

    def test_unknown_missing_and_duplicate_fields_refuse(self):
        for mutate in (lambda value: value.update(extra=True), lambda value: value.pop("wasmSha256")):
            values = fixture()
            mutate(values[0])
            with self.assertRaises(ValueError):
                observer.validate_readback(*values)
        with self.assertRaises(ValueError):
            observer.closed_json('{"version":1,"version":1}')

    def test_process_source_mapping_and_artifact_substitution_refuse(self):
        changes = {"runnerPid": 44, "runnerStartTicks": "125", "workerdPid": 44,
            "workerdStartTicks": "125", "namespaceId": "another-namespace",
            "workerName": "another-worker", "persistenceRoot": "/another/root",
            "sourceStorePath": "/another/source", "wasmSha256": "c" * 64,
            "buildDerivedSourceDigest": "d" * 64, "shimSha256": "e" * 64,
            "workerdExecutableSha256": "f" * 64, "wasmByteSize": "2048"}
        for field, value in changes.items():
            with self.subTest(field=field):
                values = fixture()
                values[0][field] = value
                with self.assertRaises(ValueError):
                    observer.validate_readback(*values)
        values = fixture()
        values[4]["parentPid"] = 41
        with self.assertRaises(ValueError):
            observer.validate_readback(*values)
        values = fixture()
        values[2]["sourceDigest"] = "0" * 64
        with self.assertRaises(ValueError):
            observer.validate_readback(*values)

    def test_purpose_version_remote_and_spelling_refuse(self):
        for field, value in {"runnerPid": True, "wasmByteSize": "01",
                "version": True, "miniflareVersion": "unsupported",
                "observationScope": "hosted", "bindingName": "OTHER",
                "namespaceUniqueKey": "other", "namespaceObjectId": "invalid",
                "observedAt": "2026-10-01T00:00:00.000+01:00"}.items():
            with self.subTest(field=field):
                values = fixture()
                values[0][field] = value
                with self.assertRaises(ValueError):
                    observer.validate_readback(*values)
        values = fixture()
        configuration = json.loads(values[1]["configurationBytes"])
        configuration["r2Buckets"]["REGISTRY_BUCKET"] = {
            "id": "controlled-namespace", "remoteProxyConnectionString": "https://example.invalid"}
        values[1]["configurationBytes"] = json.dumps(configuration).encode()
        with self.assertRaises(ValueError):
            observer.validate_readback(*values)

    def test_owner_private_selection_symlink_fifo_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private.json"
            private.write_bytes(b"{}")
            private.chmod(0o600)
            self.assertEqual(observer.bounded_file(private, 2), b"{}")
            self.assertEqual(observer.hash_file(private, 2), (hashlib.sha256(b"{}").hexdigest(), "2"))
            with self.assertRaises(ValueError):
                observer.bounded_file(private, 1)
            private.chmod(0o644)
            with self.assertRaises(ValueError):
                observer.bounded_file(private, 2)
            alias = root / "alias"
            alias.symlink_to(private)
            with self.assertRaises(OSError):
                observer.bounded_file(alias, 2)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                observer.bounded_file(fifo, 2)

    def test_actual_socket_peer_join_and_oversized_reply_refusal(self):
        for wrong_peer, byte_count in ((False, 2), (True, 2), (False, 16385)):
            with self.subTest(wrong_peer=wrong_peer, byte_count=byte_count):
                with tempfile.TemporaryDirectory() as directory:
                    socket_file = Path(directory) / "control.sock"
                    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    server.bind(str(socket_file))
                    socket_file.chmod(0o600)
                    server.listen(1)
                    requests = []

                    def reply():
                        with server:
                            connection, _ = server.accept()
                            with connection:
                                connection.settimeout(2)
                                body = bytearray()
                                while block := connection.recv(4096):
                                    body.extend(block)
                                requests.append(bytes(body))
                                try:
                                    connection.sendall(b"{}" if byte_count == 2 else b"x" * byte_count)
                                except (BrokenPipeError, ConnectionResetError):
                                    pass

                    thread = threading.Thread(target=reply)
                    thread.start()
                    pin = {"pid": os.getpid() + int(wrong_peer), "ownerUid": os.getuid()}
                    try:
                        if wrong_peer or byte_count > 16384:
                            with self.assertRaises(ValueError):
                                observer.read_socket_reply(socket_file, pin)
                        else:
                            self.assertEqual(observer.read_socket_reply(socket_file, pin), {})
                            self.assertEqual(requests, [b'{"version":1,"kind":"oci-sdk-namespace-readback"}'])
                    finally:
                        thread.join(timeout=3)
                        self.assertFalse(thread.is_alive())

    def test_actual_process_executable_lifetime_and_wrong_selection(self):
        executable = (Path("/proc") / str(os.getpid()) / "exe").resolve()
        actual = observer.process_identity(os.getpid(), executable)
        self.assertEqual(actual["pid"], os.getpid())
        self.assertEqual(actual["ownerUid"], os.getuid())
        self.assertGreater(int(actual["startTicks"]), 0)
        with self.assertRaises((ValueError, OSError)):
            observer.process_identity(os.getpid(), Path(__file__))


if __name__ == "__main__":
    unittest.main()

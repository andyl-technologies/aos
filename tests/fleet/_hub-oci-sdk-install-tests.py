"""Controlled local custody/correlation gates; no KV or provider is contacted."""

import base64
import importlib.util
import json
import os
import socket
import threading
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("oci_install", Path(__file__).with_name("_hub-oci-sdk-install.py"))
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.retained = tempfile.TemporaryDirectory(prefix="oci-install-", dir=".")
        self.directory = Path(".") / Path(self.retained.name).name
        self.directory.chmod(0o700)

    def tearDown(self):
        self.retained.cleanup()

    def reply(self, artifact=b"controlled artifact"):
        runner = {"pid": os.getpid(), "startTicks": "123"}
        key = "oci-sdk-emulator-v1-" + "ab" * 32
        reply = {"version": 1, "status": "stored", "key": key,
                 "artifactSha256": INSTALL.digest(artifact), "byteSize": str(len(artifact)),
                 "runnerPid": runner["pid"], "runnerStartTicks": runner["startTicks"],
                 "artifactBase64": base64.b64encode(artifact).decode()}
        return reply, artifact, key, runner

    def test_actual_readback_bytes_and_exact_lifetime_are_required(self):
        reply, artifact, key, runner = self.reply()
        self.assertEqual(INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner), artifact)
        reply["runnerStartTicks"] = "124"
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)

    def test_hash_summary_cannot_replace_changed_or_incomplete_bytes(self):
        reply, artifact, key, runner = self.reply()
        reply["artifactBase64"] = base64.b64encode(b"changed").decode()
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)
        reply["artifactBase64"] = ""
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)

    def test_unknown_or_acceptance_boolean_is_not_a_staging_receipt(self):
        reply, artifact, key, runner = self.reply()
        reply["status"] = "unknown"
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)
        reply["status"] = "stored"
        reply["accepted"] = True
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)

    def test_private_original_is_no_replace_and_links_public_modes_refuse(self):
        original = self.directory / "request.json"
        INSTALL.write_new(original, b"original")
        self.assertEqual(INSTALL.private_file(original, 100), b"original")
        with self.assertRaises(OSError):
            INSTALL.write_new(original, b"changed")
        link = self.directory / "link"
        link.symlink_to("request.json")
        with self.assertRaises(OSError):
            INSTALL.private_file(link, 100)
        original.chmod(0o644)
        with self.assertRaises(ValueError):
            INSTALL.private_file(original, 100)

    def test_actual_unix_peer_is_checked_before_sending_original(self):
        socket_path = self.directory / "control.socket"
        observed = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(socket_path))
            socket_path.chmod(0o600)
            server.listen(1)

            def accept():
                with server.accept()[0] as peer:
                    peer.settimeout(2)
                    observed.append(peer.recv(1024))

            child = threading.Thread(target=accept)
            child.start()
            with self.assertRaises(INSTALL.StagingExchangeError) as refused:
                INSTALL.exchange(socket_path, b"original must stay unsent",
                                 {"pid": os.getpid() + 1, "ownerUid": os.geteuid()})
            child.join(timeout=3)

        self.assertFalse(child.is_alive())
        self.assertEqual(observed, [b""])
        self.assertEqual(refused.exception.partial, b"")

    def test_actual_unix_exchange_retains_original_and_reply_bounds(self):
        socket_path = self.directory / "control.socket"
        request = b"exact original"
        observed = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(socket_path))
            socket_path.chmod(0o600)
            server.listen(1)

            def accept():
                with server.accept()[0] as peer:
                    peer.settimeout(2)
                    observed.append(peer.recv(1024))
                    peer.sendall(b"x" * 65537)

            child = threading.Thread(target=accept)
            child.start()
            with self.assertRaises(INSTALL.StagingExchangeError) as refused:
                INSTALL.exchange(socket_path, request,
                                 {"pid": os.getpid(), "ownerUid": os.geteuid()})
            child.join(timeout=3)

        self.assertFalse(child.is_alive())
        self.assertEqual(observed, [request])
        self.assertGreater(len(refused.exception.partial), 65536)
        self.assertLessEqual(len(refused.exception.partial), 65536 + 4096)

    def test_namespace_duplicates_wrong_slot_and_reply_bounds_refuse(self):
        with self.assertRaises(ValueError):
            INSTALL.closed_json(b'{"key":"first","key":"last"}')
        reply, artifact, key, runner = self.reply()
        reply["key"] = "direct-upload-acceptance-" + "ab" * 32
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)
        reply["key"] = key
        reply["artifactBase64"] = "A" * 50000
        with self.assertRaises(ValueError):
            INSTALL.verify_reply(json.dumps(reply).encode(), artifact, key, runner)


if __name__ == "__main__":
    unittest.main()

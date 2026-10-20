"""Checks unchanged backend exchanges and bounded qualification controls."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

specification = importlib.util.spec_from_file_location("interceptor", sys.argv[1])
interceptor = importlib.util.module_from_spec(specification)
specification.loader.exec_module(interceptor)


class InterceptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.backend = self.root / "backend"
        self.backend.write_text(
            "#!" + sys.executable + "\nimport sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(sys.argv[1].encode() + b':' + payload)\n")
        self.backend.chmod(0o700)
        interceptor.BACKEND = str(self.backend)
        interceptor.ROOT = str(self.root)

    def test_delegate_preserves_exact_exchange_bytes(self):
        payload = b'{"native":"unchanged"}'
        status, response = interceptor.delegate(payload, "observe", 1)
        self.assertEqual(status, 0)
        self.assertEqual(response, b"observe:" + payload)

    def test_failed_backend_does_not_become_success(self):
        self.backend.write_text("#!" + sys.executable + "\nimport sys\nsys.exit(73)\n")
        status, response = interceptor.delegate(b"{}", "remove", 1)
        self.assertEqual(status, 73)
        self.assertEqual(response, b"")

    def test_delegate_response_is_bounded(self):
        previous = interceptor.LIMIT
        self.addCleanup(setattr, interceptor, "LIMIT", previous)
        interceptor.LIMIT = 4
        with self.assertRaises(ValueError):
            interceptor.delegate(b"0123456789", "apply", 1)

    def test_delegate_deadline_is_bounded(self):
        self.backend.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(5)\n")
        with self.assertRaises(TimeoutError):
            interceptor.delegate(b"{}", "apply", 0.05)

    def test_writable_control_directory_is_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            interceptor.read_control("armed.json")

    def test_symbolic_control_directory_is_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        interceptor.ROOT = str(link)
        with self.assertRaises(OSError):
            interceptor.read_control("armed.json")

    def test_capture_pins_real_bytes_and_exact_identity(self):
        identity = {"effect": "native", "revision": "sha256:revision",
                    "action": "apply", "operation": "apply"}
        response = b'{"resource":"actual"}'
        interceptor.retain_capture(identity, response)
        receipt = json.loads((self.root / "captured.json").read_bytes())
        self.assertEqual(receipt["responseSha256"], "sha256:" + hashlib.sha256(response).hexdigest())
        self.assertEqual(receipt["responseSize"], len(response))
        self.assertEqual({key: receipt[key] for key in identity}, identity)
        self.assertEqual((self.root / "captured.json").stat().st_mode & 0o777, 0o600)


unittest.main(argv=[sys.argv[0]])

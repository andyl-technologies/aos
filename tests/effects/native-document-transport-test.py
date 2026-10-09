"""Checks lossless fleet transport with actual source-built Python and Bash."""

import base64
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
import zlib


SOURCE = Path(sys.argv.pop(1)).resolve(strict=True)
FLIGHT_SOURCE = Path(sys.argv.pop(1)).resolve(strict=True)
BASH = Path(sys.argv.pop(1)).resolve(strict=True)
COREUTILS = Path(sys.argv.pop(1)).resolve(strict=True)
PYTHON = Path(sys.executable).resolve(strict=True)
for tool in (BASH, COREUTILS, PYTHON):
    if not tool.is_relative_to("/nix/store"):
        raise ValueError("transport checks require source-built AOS tools")


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


transport = load_module("native_document_transport", SOURCE)
flight = load_module("native_activation_flight", FLIGHT_SOURCE)


class LocalGuest:
    """Runs the same guest pipeline locally, without qualifying guest state."""

    def succeed(self, command):
        result = subprocess.run(
            [str(BASH), "-c", command], check=True, capture_output=True, text=True
        )
        self.encoded_stdout = result.stdout
        return result.stdout


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "document"
        self.guest = LocalGuest()

    def read_document(self, command, maximum=None):
        return transport.compressed_output(
            self.guest, command, shell=str(BASH), python=str(PYTHON), maximum=maximum
        )

    def read_file(self):
        return self.read_document(f"{COREUTILS}/cat {shlex.quote(str(self.path))}")

    def test_large_complete_json_roundtrip_preserves_all_fields_and_bytes(self):
        document = {
            "desired": {"nodes": {
                str(index): {"input": "full schema and input ü\n" * 200, "identity": [index]}
                for index in range(600)
            }},
            "records": [{"sequence": index, "event": "retained"} for index in range(600)],
        }
        original = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        self.assertGreater(len(original.encode()), 1_800_000)
        self.path.write_text(original, encoding="utf-8")

        decoded = self.read_file()

        self.assertEqual(decoded.encode(), original.encode())
        self.assertEqual(json.loads(decoded), document)
        self.assertLess(len(self.guest.encoded_stdout), len(original.encode()) // 20)

    def test_jsonl_roundtrip_preserves_every_event_and_order(self):
        events = [{"sequence": index, "text": "line\nwith ü"} for index in range(1000)]
        original = "".join(json.dumps(event, ensure_ascii=False) + "\r\n" for event in events)
        self.path.write_text(original, encoding="utf-8")

        decoded = self.read_file()

        self.assertEqual(decoded, original)
        self.assertEqual([json.loads(line) for line in decoded.splitlines()], events)

    def test_partial_stdout_does_not_hide_a_failed_producer(self):
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            self.read_document("printf '%s' partial; exit 17")
        self.assertEqual(failure.exception.returncode, 17)

    def test_missing_command_fails_instead_of_returning_an_empty_document(self):
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            self.read_document(shlex.quote(str(Path(self.directory.name) / "missing-command")))
        self.assertEqual(failure.exception.returncode, 127)

    def test_actual_flight_read_bound_checks_decoded_bytes(self):
        flight.native_document = self.read_document
        flight.COREUTILS = str(COREUTILS)
        original = "ü" * 32
        self.path.write_text(original, encoding="utf-8")

        self.assertEqual(flight.read_bounded(str(self.path), maximum=64), original)
        self.path.write_bytes(b"x" * 65)
        with self.assertRaisesRegex(RuntimeError, "exceeds its read bound"):
            flight.read_bounded(str(self.path), maximum=64)
        self.assertEqual(flight.read_bounded.__defaults__, (16 * 1024 * 1024,))

    def test_invalid_compressed_transport_is_rejected(self):
        class InvalidGuest:
            def __init__(self, value):
                self.value = value

            def succeed(self, command):
                return self.value

        for invalid in (
            "invalid base64!",
            base64.b64encode(zlib.compress(b"document")[:-1]).decode(),
            base64.b64encode(zlib.compress(b"document") + b"trailing").decode(),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                transport.compressed_output(
                    InvalidGuest(invalid), "", shell=str(BASH), python=str(PYTHON)
                )


if __name__ == "__main__":
    unittest.main()

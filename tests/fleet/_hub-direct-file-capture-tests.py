"""Exercise actual file capture with a bounded transport and real local files.

These checks execute the checked-in guest reader against disk files. They do
not claim VM, provider, authentication or throughput coverage.
"""

import ast
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import textwrap
import unittest


class GuestFileCapture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "capture.bin"
        self.body = bytes(range(256)) * (12 * 1024)
        self.path.write_bytes(self.body)
        self.calls = 0
        self.after_capture = lambda: None

        def guest(machine, python, program, selected):
            self.calls += 1
            output = io.StringIO()
            namespace = {"selected": selected, "base64": base64, "json": json}
            with contextlib.redirect_stdout(output):
                exec(compile(textwrap.dedent(program), "guest-reader", "exec"), namespace)
            captured = output.getvalue()
            if len(captured.encode()) > 1536 * 1024:
                raise RuntimeError("bounded agent response exceeded")
            self.after_capture()
            return captured

        source = Path(__file__).with_name("_hub-direct-flow.py").read_text()
        tree = ast.parse(source)
        function = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "read_direct_guest_file")
        namespace = {"direct_guest_python": guest, "base64": base64,
            "hashlib": hashlib, "json": json}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "file-capture", "exec"), namespace)
        self.read = namespace["read_direct_guest_file"]

    def test_large_binary_crosses_only_bounded_transport_responses(self):
        captured = self.read(None, "unused", str(self.path), len(self.body))

        self.assertEqual(captured, self.body)
        self.assertGreater(self.calls, 1)

    def test_empty_file_and_size_limit(self):
        with self.assertRaises(ValueError):
            self.read(None, "unused", str(self.path), 1)
        self.path.write_bytes(b"")

        self.assertEqual(self.read(None, "unused", str(self.path), 0), b"")

    def test_symlink_is_not_followed(self):
        link = self.path.with_name("link")
        link.symlink_to(self.path)

        with self.assertRaises(OSError):
            self.read(None, "unused", str(link), len(self.body))

    def test_file_changes_between_transport_calls_are_refused(self):
        def mutate():
            if self.calls == 1:
                with self.path.open("r+b") as stream:
                    stream.write(b"changed")

        self.after_capture = mutate

        with self.assertRaises(ValueError):
            self.read(None, "unused", str(self.path), len(self.body))


if __name__ == "__main__":
    unittest.main()

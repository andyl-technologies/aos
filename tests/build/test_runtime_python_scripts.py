"""Checks interpreter pinning for installed Python scripts and data files."""

import os
from pathlib import Path
import tempfile
import unittest

from runtime_python_scripts import pin_python_scripts


class PythonScriptTests(unittest.TestCase):
    def test_env_flags_body_and_metadata_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.py"
            path.write_bytes(b"#!/usr/bin/env -S python3 -B\nprint('example')\n")
            path.chmod(0o555)
            os.utime(path, ns=(1000000000, 2000000000))

            pin_python_scripts(directory)

            self.assertEqual(
                path.read_bytes(),
                f"#!{directory}/bin/python3 -B\nprint('example')\n".encode(),
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o555)
            self.assertEqual(path.stat().st_mtime_ns, 2000000000)

    def test_absolute_interpreter_and_hard_links_are_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.py"
            path.write_bytes(b"#!/usr/bin/python3.8\npass\n")
            alias = Path(directory) / "alias.py"
            os.link(path, alias)

            pin_python_scripts(directory)

            self.assertEqual(path.read_bytes(), f"#!{directory}/bin/python3\npass\n".encode())
            self.assertEqual(path.stat().st_ino, alias.stat().st_ino)

    def test_other_interpreters_binary_data_and_symlinks_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            files = {"shell": b"#!/bin/sh\ntrue\n", "binary": b"\x00\x01\xff\n"}
            for name, contents in files.items():
                (root / name).write_bytes(contents)
            external = Path(directory) / "external"
            external.write_bytes(b"#!/usr/bin/python3\npass\n")
            (root / "link").symlink_to(external)

            pin_python_scripts(str(root))

            for name, contents in files.items():
                self.assertEqual((root / name).read_bytes(), contents)
            self.assertEqual(external.read_bytes(), b"#!/usr/bin/python3\npass\n")

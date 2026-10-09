# SPDX-License-Identifier: MIT
"""Exercises finite preflight and unchanged-file custody for native witnesses."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "crucible_native_image_custody", Path(__file__).with_name("native-controller-image-check.py"))
custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custody)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.original_limits = custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES
        custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES = 16, 24, 2

    def tearDown(self):
        custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES = self.original_limits
        self.temporary.cleanup()

    def file(self, name, data=b"original"):
        target = self.root / name
        target.write_bytes(data)
        target.chmod(0o600)
        return target

    def test_symlink_refused_before_destination(self):
        source = self.file("source")
        (self.root / "symbolic").symlink_to(source)
        with self.assertRaises(OSError):
            custody.checked_file(self.root / "symbolic")

    def test_shared_inode_refused(self):
        source = self.file("source")
        os.link(source, self.root / "linked")
        with self.assertRaises(ValueError):
            custody.checked_file(source)

    def test_count_refused_before_copy(self):
        source = self.root / "tree"
        source.mkdir()
        for index in range(3):
            (source / str(index)).write_bytes(b"x")
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_tree(source, destination)
        self.assertFalse(destination.exists())

    def test_total_refused_before_copy(self):
        source = self.root / "tree"
        source.mkdir()
        for index in range(2):
            (source / str(index)).write_bytes(b"x" * 13)
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_tree(source, destination)
        self.assertFalse(destination.exists())

    def test_oversize_refused(self):
        with self.assertRaises(ValueError):
            custody.checked_file(self.file("source", b"x" * 17))

    def test_changed_source_refused_before_destination(self):
        source = self.file("source")
        descriptor, original = custody.checked_file(source)
        os.close(descriptor)
        source.write_bytes(b"new extent")
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_file(source, destination, original, 0o400)
        self.assertFalse(destination.exists())

    def test_fresh_inode_exact_bytes_and_private_mode(self):
        source = self.file("source")
        descriptor, original = custody.checked_file(source)
        os.close(descriptor)
        destination = self.root / "copy"

        measured = custody.copy_file(source, destination, original, 0o400)

        self.assertEqual(measured, custody.digest(source))
        self.assertEqual(destination.read_bytes(), b"original")
        self.assertNotEqual(source.stat().st_ino, destination.stat().st_ino)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o400)


if __name__ == "__main__":
    unittest.main()

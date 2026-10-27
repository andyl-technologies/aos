# SPDX-License-Identifier: MIT
"""Exercises the finite filesystem preflight used by Terminal native witnesses."""

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).with_name("terminal-continuation-check.py")


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        names = {"checked_file", "fingerprint", "read_result", "file_census",
                 "copy_checked", "tree_census", "copy_tree"}
        tree = ast.parse(SOURCE.read_text())
        body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(len(body), len(names))
        self.policy = {"os": os, "stat": stat, "json": json, "hashlib": hashlib,
                       "MAX_RESULT_BYTES": 16, "MAX_TOTAL_BYTES": 32,
                       "MAX_FILE_BYTES": 16, "MAX_FILES": 2}
        exec(compile(ast.Module(body=body, type_ignores=[]), str(SOURCE), "exec"), self.policy)

    def tearDown(self):
        self.temporary.cleanup()

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_result_bound_before_read(self):
        path = self.file("result", b" " * 17)
        with self.assertRaises(ValueError):
            self.policy["read_result"](path)

    def test_count_bound_before_copy(self):
        paths = [self.file(str(index), b"a") for index in range(3)]
        with self.assertRaises(ValueError):
            self.policy["file_census"](iter(paths), 16)

    def test_cumulative_bound_before_copy(self):
        paths = [self.file("a", b"1234"), self.file("b", b"5678")]
        with self.assertRaises(ValueError):
            self.policy["file_census"](paths, 16, 7)

    def test_singlelink_custody_required(self):
        path = self.file("a", b"a")
        os.link(path, self.root / "alias")
        with self.assertRaises(ValueError):
            self.policy["checked_file"](path, 16)

    def test_symlink_refused(self):
        path = self.file("a", b"a")
        symbolic = self.root / "symbolic"
        symbolic.symlink_to(path)
        with self.assertRaises(OSError):
            self.policy["checked_file"](symbolic, 16)

    def test_changed_source_refused_before_destination_allocation(self):
        path = self.file("a", b"a")
        census, _ = self.policy["file_census"]([path], 16)
        path.write_bytes(b"different")
        target = self.root / "target"
        with self.assertRaises(ValueError):
            self.policy["copy_checked"](path, target, census[0][1], 16)
        self.assertFalse(target.exists())

    def test_copy_same_descriptor_exact_digest_and_private_mode(self):
        path = self.file("a", b"original")
        census, _ = self.policy["file_census"]([path], 16)
        target = self.root / "target"

        digest = self.policy["copy_checked"](path, target, census[0][1], 16)

        self.assertEqual(digest, hashlib.sha256(b"original").hexdigest())
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(target.stat().st_mode & 0o777, 0o400)
        self.assertNotEqual(path.stat().st_ino, target.stat().st_ino)

    def test_tree_symbolic_directory_refused(self):
        directory = self.root / "tree"
        directory.mkdir()
        (directory / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.policy["tree_census"](directory)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: MIT
"""Checks finite private model asset bindings before any simulator is launched."""

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("model_assets", sys.argv.pop(1))
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class AssetChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "kernel.elf"
        self.path.write_bytes(b"original")
        self.path.chmod(0o600)
        self.record = {"file": "kernel.elf", "bytes": "8",
                       "sha256": hashlib.sha256(b"original").hexdigest()}

    def test_exact_original_body(self):
        self.assertEqual(assets.verify_asset(self.root, self.record, "kernel.elf"),
                         {"bytes": "8", "sha256": self.record["sha256"]})

    def test_unknown_role(self):
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "other.elf")

    def test_changed_body(self):
        self.path.write_bytes(b"modified")
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_private_permissions(self):
        self.path.chmod(0o640)
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_no_shared_inode(self):
        os.link(self.path, self.root / "alias")
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_no_symbolic_leaf(self):
        self.path.rename(self.root / "original")
        self.path.symlink_to("original")
        with self.assertRaises(OSError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_noncanonical_extent(self):
        self.record["bytes"] = "08"
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_extent_preflight(self):
        self.record["bytes"] = str(assets.MAX_ASSET_BYTES + 1)
        with self.assertRaises(ValueError):
            assets.verify_asset(self.root, self.record, "kernel.elf")

    def test_empty_python_module_is_measured(self):
        self.path.unlink()
        empty = self.root / "__init__.py"
        empty.write_bytes(b"")
        empty.chmod(0o600)
        observed = assets.configuration_tree(self.root)
        self.assertEqual(observed["bytes"], "0")
        self.assertEqual(observed["files"], "1")

    def test_configuration_symbolic_directory(self):
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            assets.configuration_tree(self.root)

    def test_empty_directories_consume_member_credit(self):
        previous = assets.MAX_CONFIG_FILES
        self.addCleanup(setattr, assets, "MAX_CONFIG_FILES", previous)
        assets.MAX_CONFIG_FILES = 3
        for index in range(3):
            (self.root / str(index)).mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            assets.configuration_tree(self.root)


if __name__ == "__main__":
    unittest.main()

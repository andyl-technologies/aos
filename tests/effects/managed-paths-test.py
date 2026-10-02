"""Checks image baseline leaf inventories against immutable source layouts."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

specification = importlib.util.spec_from_file_location("managed_paths", sys.argv.pop(1))
managed_paths = importlib.util.module_from_spec(specification)
specification.loader.exec_module(managed_paths)


class ManagedInventoryTests(unittest.TestCase):
    def test_inventory_records_leaves_without_claiming_user_parent_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "nested").mkdir()
            (source / "nested" / "service.conf").write_text("managed")
            (source / "alias.conf").symlink_to("nested/service.conf")
            paths = set()
            managed_paths.visit(source, "libvirt", [], paths)
            self.assertEqual(paths, {"libvirt/nested/service.conf", "libvirt/alias.conf"})
            self.assertNotIn("libvirt", paths)
            self.assertNotIn("libvirt/nested", paths)

    def test_symlink_directory_cycle_fails_before_publishing_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "cycle").symlink_to(".")
            with self.assertRaises(ValueError):
                managed_paths.visit(source, "libvirt", [], set())


if __name__ == "__main__":
    unittest.main()

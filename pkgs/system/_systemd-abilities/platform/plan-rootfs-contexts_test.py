"""Tests partition-aware SELinux labels from actual /etc metadata aliases."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


planner_source, adapter_source = map(Path, sys.argv[1:3])
del sys.argv[1:3]
spec = importlib.util.spec_from_file_location("aos_rootfs_context_adapter", adapter_source)
if spec is None or spec.loader is None:
    raise ValueError("cannot load the rootfs context adapter")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
planner = adapter.load_planner(planner_source)


class Resolver:
    """Distinguishes conventional unit paths from generic immutable data."""

    def lookup(self, path, _kind):
        if path.startswith("/etc/systemd/system/"):
            return "system_u:object_r:systemd_unit_t"
        if path.startswith("/nix"):
            return "system_u:object_r:default_t"
        if path == "/etc" or path.startswith("/etc/"):
            return "system_u:object_r:etc_t"
        return "system_u:object_r:root_t"


def metadata_entry(path, kind, target=None):
    """Creates metadata DATA without claiming any root-image inode."""

    return planner.InventoryEntry(
        path=path,
        source=None,
        mode=planner.kind_mode(kind),
        kind=kind,
        inode_key=(0, 99),
        symlink_target=target,
    )


class RootfsContextTest(unittest.TestCase):
    """Covers namespace confinement, physical custody and alias propagation."""

    def test_metadata_labels_only_its_actual_store_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc").mkdir()
            selected = "/usr/lib/aos/nix/store/" + "a" * 32 + "-unit/reference.service"
            inactive = "/usr/lib/aos/nix/store/" + "b" * 32 + "-unit/reference.service"
            for path in (selected, inactive):
                source = root / path.lstrip("/")
                source.parent.mkdir(parents=True)
                source.write_text("[Service]\nExecStart=/fixed\n")
                source.chmod(0o444)
            physical = planner.inventory_tree(root)
            directory = planner.InodeKind.directory
            metadata = [
                metadata_entry(path, directory)
                for path in ("/", "/systemd", "/systemd/system")
            ]
            metadata.append(
                metadata_entry(
                    "/systemd/system/reference.service",
                    planner.InodeKind.symlink,
                    "/nix" + selected.removeprefix("/usr/lib/aos/nix"),
                )
            )

            labels = adapter.plan_root_labels(planner, physical, metadata, Resolver())
            observed = {label.path: label.context for label in labels}

            self.assertEqual(set(observed), {entry.path for entry in physical})
            self.assertEqual(observed[selected], "system_u:object_r:systemd_unit_t")
            self.assertEqual(observed[inactive], "system_u:object_r:usr_t")

    def test_metadata_cannot_replace_a_physical_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc").mkdir()
            (root / "etc/reference").write_text("physical original")
            physical = planner.inventory_tree(root)
            metadata = [
                metadata_entry("/reference", planner.InodeKind.symlink, "/elsewhere")
            ]

            with self.assertRaisesRegex(planner.PlanError, "hides a root-image inode"):
                adapter.compose_etc_inventory(planner, physical, metadata)

    def test_metadata_directories_keep_no_physical_inode_identity(self):
        entry = metadata_entry("/systemd", planner.InodeKind.directory)

        combined = adapter.compose_etc_inventory(planner, [], [entry])

        self.assertEqual(len(combined), 1)
        self.assertEqual(combined[0].path, "/etc/systemd")
        self.assertIsNone(combined[0].inode_key)
        self.assertIsNone(combined[0].source)

    def test_noncanonical_and_duplicate_metadata_paths_are_rejected(self):
        entry = metadata_entry("/reference", planner.InodeKind.symlink, "/elsewhere")
        for path in (
            "reference", "/../usr", "/systemd//unit", "/systemd/./unit", "/bad\npath"
        ):
            with self.subTest(path=path):
                with self.assertRaises(planner.PlanError):
                    adapter.compose_etc_inventory(planner, [], [replace(entry, path=path)])
        with self.assertRaisesRegex(planner.PlanError, "duplicate"):
            adapter.compose_etc_inventory(planner, [], [entry, entry])


if __name__ == "__main__":
    unittest.main()

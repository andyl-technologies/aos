"""Checks canonical directory sources and preserved composefs symlink leaves."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


builder = Path(sys.argv.pop(1)).resolve(strict=True)
specification = importlib.util.spec_from_file_location("composefs_dump", builder)
composefs_dump = importlib.util.module_from_spec(specification)
specification.loader.exec_module(composefs_dump)


class DirectorySourceTests(unittest.TestCase):
    def test_directory_aliases_emit_canonical_regular_files_and_preserve_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            source = root / "unit-payload"
            source.mkdir()
            (source / "nested").mkdir()
            (source / "example.service").write_text("[Service]\nExecStart=true\n")
            (source / "nested" / "other.service").write_text("[Service]\nExecStart=true\n")
            (source / "alias.service").symlink_to("example.service")
            (source / "multi-user.target.wants").mkdir()
            (source / "multi-user.target.wants" / "example.service").symlink_to("../example.service")
            outside = root / "outside"
            outside.mkdir()
            (outside / "unselected.service").write_text("not selected\n")
            (source / "linked-directory").symlink_to("../outside", target_is_directory=True)

            manager = root / "manager-output"
            manager.mkdir()
            (manager / "systemd-units").symlink_to(source, target_is_directory=True)
            parent_alias = root / "manager-alias"
            parent_alias.symlink_to(manager, target_is_directory=True)

            for selected in [source, manager / "systemd-units", parent_alias / "systemd-units"]:
                with self.subTest(source=selected):
                    config = root / "config.json"
                    config.write_text(json.dumps([{
                        "target": "systemd/system", "source": str(selected),
                        "mode": "symlink", "uid": "0", "gid": "0",
                    }]))

                    result = subprocess.run(
                        [sys.executable, str(builder), str(config)],
                        capture_output=True, text=True, check=True,
                    )
                    entries = {
                        fields[0]: fields
                        for fields in (line.split() for line in result.stdout.splitlines())
                    }

                    for relative in ["example.service", "nested/other.service"]:
                        entry = entries[f"/systemd/system/{relative}"]
                        self.assertEqual(entry[2], "120777")
                        self.assertEqual(entry[8], str(source / relative))
                    for relative, target in [
                        ("alias.service", "example.service"),
                        ("multi-user.target.wants/example.service", "../example.service"),
                        ("linked-directory", "../outside"),
                    ]:
                        entry = entries[f"/systemd/system/{relative}"]
                        self.assertEqual(entry[2], "120777")
                        self.assertEqual(entry[8], target)
                    for relative in ["", "/nested", "/multi-user.target.wants"]:
                        entry = entries[f"/systemd/system{relative}"]
                        self.assertEqual(entry[2], "40755")
                        self.assertEqual(entry[8], "-")
                    self.assertNotIn("/systemd/system/linked-directory/unselected.service", entries)

    def test_missing_directory_alias_fails_before_emitting_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing-alias"
            source.symlink_to("absent", target_is_directory=True)
            entries = {}

            with self.assertRaises(FileNotFoundError):
                composefs_dump.recurse_symlink_source(
                    "/systemd/system", str(source), {"uid": "0", "gid": "0"}, entries,
                )

            self.assertEqual(entries, {})


if __name__ == "__main__":
    unittest.main()

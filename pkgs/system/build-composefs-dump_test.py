"""Regression tests for composefs dump SELinux xattr encoding."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("build-composefs-dump.py")
SPEC = importlib.util.spec_from_file_location("build_composefs_dump", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
composefs_dump = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(composefs_dump)


class XattrCodecTest(unittest.TestCase):
    """Covers byte escaping and context attachment to actual inode kinds."""

    def test_all_separator_and_non_ascii_bytes_are_escaped(self) -> None:
        self.assertEqual(
            composefs_dump.escape_xattr_value(b"a b=c\\d\n\x80\x00"),
            r"a\x20b\x3dc\\d\x0a\x80\x00",
        )

    def test_context_has_one_explicit_trailing_nul(self) -> None:
        entry = composefs_dump.ComposefsPath(
            {"target": "/etc/sample", "uid": "0", "gid": "0"},
            size=1,
            filetype=composefs_dump.FileType.file,
            mode="0644",
            payload="etc/sample",
        )
        entry.selinux_context = "system_u:object_r:etc_t:s0"
        self.assertEqual(
            entry.write_line(),
            "/etc/sample 1 100644 1 0 0 0 1.0 etc/sample - - "
            "security.selinux=system_u:object_r:etc_t:s0\\x00",
        )

    def test_context_map_keys_include_actual_inode_kind(self) -> None:
        entries = [
            composefs_dump.ComposefsPath(
                {"target": "/etc", "uid": "0", "gid": "0"},
                size=4096,
                filetype=composefs_dump.FileType.directory,
                mode="0755",
                payload="-",
            ),
            composefs_dump.ComposefsPath(
                {"target": "/etc/link", "uid": "0", "gid": "0"},
                size=4,
                filetype=composefs_dump.FileType.symlink,
                mode="0777",
                payload="file",
            ),
        ]
        contexts = {
            ("/etc", composefs_dump.FileType.directory):
                "system_u:object_r:etc_t:s0",
            ("/etc/link", composefs_dump.FileType.symlink):
                "system_u:object_r:etc_t:s0",
        }
        composefs_dump.apply_context_map(entries, contexts)
        self.assertTrue(all(entry.selinux_context for entry in entries))

    def test_missing_or_default_context_is_rejected(self) -> None:
        entry = composefs_dump.ComposefsPath(
            {"target": "/etc", "uid": "0", "gid": "0"},
            size=4096,
            filetype=composefs_dump.FileType.directory,
            mode="0755",
            payload="-",
        )
        with self.assertRaisesRegex(ValueError, "no entry"):
            composefs_dump.apply_context_map([entry], {})
        with self.assertRaisesRegex(ValueError, "unsafe"):
            composefs_dump.apply_context_map(
                [entry],
                {
                    ("/etc", composefs_dump.FileType.directory):
                        "system_u:object_r:default_t:s0"
                },
            )


class DisabledPathCompatibilityTest(unittest.TestCase):
    """Locks the no-context-map stdout to the pre-SELinux format."""

    def test_no_option_output_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary, "etc.json")
            source = Path(temporary, "source")
            source.write_text("x", encoding="utf-8")
            config.write_text(
                json.dumps(
                    [
                        {
                            "target": "sample",
                            "source": str(source),
                            "mode": "0644",
                            "uid": "0",
                            "gid": "0",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(config)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(
            result.stdout,
            "/ 4096 40755 1 0 0 0 0.0 - - -\n"
            "/sample 1 100644 1 0 0 0 1.0 sample - -\n",
        )
        self.assertNotIn("security.selinux", result.stdout)


if __name__ == "__main__":
    unittest.main()

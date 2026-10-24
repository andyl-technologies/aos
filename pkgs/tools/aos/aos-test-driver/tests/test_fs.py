"""Byte correctness and allocation regressions for private VM disks."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aos_test_driver.fs import clone_or_copy


class SparseCopyTests(unittest.TestCase):
    def test_fallback_preserves_bytes_holes_and_partial_zero_tail(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "source"
            target = Path(scratch) / "target"
            with source.open("wb") as stream:
                stream.write(b"header")
                stream.seek(16 * 1024**2)
                stream.write(b"tail")
                stream.truncate(20 * 1024**2 + 17)
            target.write_bytes(b"stale" * 1000)

            with patch("aos_test_driver.fs.fcntl.ioctl", side_effect=OSError("no reflink")):
                self.assertFalse(clone_or_copy(str(source), str(target)))

            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertEqual(source.stat().st_size, target.stat().st_size)
            self.assertLess(target.stat().st_blocks * 512, 3 * 1024**2)

    def test_allocated_zero_blocks_become_holes(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "source"
            target = Path(scratch) / "target"
            source.write_bytes(bytes(4 * 1024**2 + 13))

            with patch("aos_test_driver.fs.fcntl.ioctl", side_effect=OSError("no reflink")):
                clone_or_copy(str(source), str(target))

            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertLess(target.stat().st_blocks * 512, 4096)

    def test_empty_file_truncates_old_destination(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "source"
            target = Path(scratch) / "target"
            source.touch()
            target.write_bytes(b"stale")

            with patch("aos_test_driver.fs.fcntl.ioctl", side_effect=OSError("no reflink")):
                clone_or_copy(str(source), str(target))

            self.assertEqual(target.read_bytes(), b"")

    def test_successful_clone_does_not_invoke_fallback(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / "source"
            target = Path(scratch) / "target"
            source.write_bytes(b"original")

            def clone(destination, _request, source_fd):
                import os
                os.write(destination, os.read(source_fd, 100))

            with patch("aos_test_driver.fs.fcntl.ioctl", side_effect=clone):
                self.assertTrue(clone_or_copy(str(source), str(target)))

            self.assertEqual(target.read_bytes(), b"original")

# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise fail-closed native metadata and inode relationship comparisons."""

import importlib.util
import sys
import unittest
from dataclasses import replace
from pathlib import Path


source = Path(__file__).with_name("verify-erofs-repack.py")
spec = importlib.util.spec_from_file_location("erofs_repack", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

REPORT = b"""Path : /sample
Size: 100  On-disk size: 60  regular file
NID: 20   Links: 1   Layout: 3   Compression ratio: 60.00%
Inode size: 32   Xattr size: 48
Uid: 0   Gid: 0  Access: 0555/r-xr-xr-x
Timestamp: 1970-01-01 00:00:00.000000000
"""


class InodeComparisonTests(unittest.TestCase):
    """Reject metadata changes while permitting changed compressed placement."""

    def test_native_report(self):
        before = module.parse_inode(REPORT)
        after = module.parse_inode(
            REPORT.replace(b"On-disk size: 60", b"On-disk size: 40")
        )
        module.compare_metadata("/sample", 0o100555, before, after)
        self.assertEqual(before.nid, 20)

    def test_missing_or_duplicate_field(self):
        for report in (REPORT.replace(b"Uid: 0", b"Owner: 0"), REPORT + REPORT):
            with self.subTest(report=report), self.assertRaises(ValueError):
                module.parse_inode(report)

    def test_changed_semantic_metadata(self):
        before = module.parse_inode(REPORT)
        for after in (
            replace(before, uid=1000),
            replace(before, gid=1000),
            replace(before, links=2),
            replace(before, permissions=0o755),
            replace(before, size=99),
            replace(before, timestamp="1970-01-02 00:00:00.000000000"),
        ):
            with self.subTest(after=after), self.assertRaises(ValueError):
                module.compare_metadata("/sample", 0o100555, before, after)

    def test_hardlink_bijection(self):
        forward, reverse = {}, {}
        module.compare_mapping("/original", 20, 50, forward, reverse)
        module.compare_mapping("/hardlink", 20, 50, forward, reverse)
        module.compare_mapping("/separate", 21, 51, forward, reverse)

        with self.assertRaisesRegex(ValueError, "hardlink split"):
            module.compare_mapping("/split", 20, 52, forward, reverse)
        with self.assertRaisesRegex(ValueError, "inodes merged"):
            module.compare_mapping("/merged", 22, 50, forward, reverse)


if __name__ == "__main__":
    unittest.main()

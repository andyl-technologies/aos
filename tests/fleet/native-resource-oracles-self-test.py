"""Checks live file oracles keep ownership claims separate from desired state."""

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


specification = importlib.util.spec_from_file_location("native_resource_oracles", sys.argv[1])
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native resource oracles")
ORACLES = importlib.util.module_from_spec(specification)
specification.loader.exec_module(ORACLES)


class NativeOracleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "configuration"
        self.path.write_bytes(b"exact live contents\n")
        self.path.chmod(0o444)

    def test_contents_and_owners_come_from_independent_sources(self):
        observed = ORACLES.file_snapshot(self.path, [{"id": "actual-owner", "path": str(self.path)}])
        self.assertEqual(observed["digest"], "sha256:" + hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(observed["owners"], ["actual-owner"])
        self.assertEqual(observed["mode"], "0444")

    def test_foreign_receipts_do_not_claim_selected_file(self):
        observed = ORACLES.file_snapshot(self.path, [{"id": "foreign-owner", "path": str(self.root / "foreign")}])
        self.assertEqual(observed["owners"], [])
        self.assertTrue(observed["exists"])

    def test_multiple_owners_are_exposed_for_qualification_rejection(self):
        receipts = [{"id": name, "path": str(self.path)} for name in ("second-owner", "first-owner")]
        self.assertEqual(ORACLES.file_snapshot(self.path, receipts)["owners"], ["first-owner", "second-owner"])

    def test_pending_old_destination_claim_is_not_lost(self):
        observed = ORACLES.file_snapshot(self.path, [{"id": "actual-owner", "path": str(self.root / "new"), "previous_path": str(self.path)}])
        self.assertEqual(observed["owners"], ["actual-owner"])

    def test_symlink_does_not_become_a_live_regular_file(self):
        alias = self.root / "alias"
        alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            ORACLES.file_snapshot(alias, [])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])

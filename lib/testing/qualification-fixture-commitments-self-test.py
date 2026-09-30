"""Checks build-time executor fixture commitments and original-root bindings."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("fixture_commitments", sys.argv.pop(1))
commitments = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commitments)
ROOT = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-fixture"
BUNDLE = "/nix/store/1123456789abcdfghijklmnpqrsvwxyz-bundle"
SOURCE = "/nix/store/2123456789abcdfghijklmnpqrsvwxyz-source"
EXECUTABLE = ROOT + "/bin/scenario"


class FixtureCommitmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.inventory = {"schema": "aos.reference-graph/v1", "roots": [BUNDLE, SOURCE],
                          "paths": [{"path": BUNDLE}, {"path": SOURCE}]}
        self.evaluations = {"controlled": {"role": "scenario", "locator": BUNDLE,
                                          "scenario_sources": [SOURCE + "/module.nix"]}}
        self.inputs = {"registry": {"schema_version": "aos.release.qualification-scenarios/v1",
                                    "platform": "x86_64-linux", "scenarios": {"native": EXECUTABLE}},
                       "fixtures": {EXECUTABLE: ROOT}}
        self.write_documents()
        (self.root / "fixture.export").write_bytes(b"original verified fixture export")

    def write_documents(self):
        (self.root / "inventory.json").write_text(json.dumps(self.inventory))
        (self.root / "evaluations.json").write_text(json.dumps(self.evaluations))

    def collect(self):
        with patch.object(commitments, "Path", return_value=self.root):
            return commitments.commit_registry(self.inputs)

    def test_original_bytes_have_build_time_commitments(self):
        recorded = self.collect()["fixture_inputs"][EXECUTABLE]
        for field, name in (("archive", "fixture.export"), ("inventory", "inventory.json"), ("evaluations", "evaluations.json")):
            self.assertEqual(recorded[field], commitments.file_commitment(self.root / name, commitments.ARCHIVE_LIMIT))

    def test_changed_archive_and_inventory_change_registry_identity(self):
        first = self.collect()
        (self.root / "fixture.export").write_bytes(b"another export")
        self.assertNotEqual(first, self.collect())
        self.inventory["paths"].append({"path": ROOT})
        self.write_documents()
        self.assertNotEqual(first, self.collect())

    def test_ambient_source_not_in_original_roots_is_rejected(self):
        self.inventory["roots"].remove(SOURCE)
        self.write_documents()
        with self.assertRaisesRegex(ValueError, "absent from the original export roots"):
            self.collect()

    def test_missing_original_graph_member_is_rejected(self):
        self.inventory["paths"].pop()
        self.write_documents()
        with self.assertRaisesRegex(ValueError, "omits an explicit root"):
            self.collect()

    def test_role_and_source_order_remain_explicit(self):
        self.evaluations["controlled"]["role"] = "candidate-baseline"
        self.write_documents()
        with self.assertRaisesRegex(ValueError, "disagree with its role"):
            self.collect()
        self.evaluations["controlled"]["scenario_sources"] = []
        self.write_documents()
        self.assertIn(EXECUTABLE, self.collect()["fixture_inputs"])

    def test_unconfigured_executable_and_predeclared_commitments_are_rejected(self):
        self.inputs["registry"]["scenarios"] = {}
        with self.assertRaisesRegex(ValueError, "not selected"):
            self.collect()
        self.inputs["registry"]["fixture_inputs"] = {}
        with self.assertRaisesRegex(ValueError, "cannot be predeclared"):
            self.collect()

    def test_symlinked_evidence_is_rejected(self):
        archive = self.root / "fixture.export"
        archive.unlink()
        archive.symlink_to("inventory.json")
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.collect()

    def test_repeated_json_keys_and_unsafe_locators_are_rejected(self):
        (self.root / "evaluations.json").write_text('{"cohort":{},"cohort":{}}')
        with self.assertRaisesRegex(ValueError, "repeats an object key"):
            self.collect()
        for locator in (SOURCE + "/../module.nix", SOURCE + "//module.nix", "/tmp/source.nix"):
            with self.assertRaisesRegex(ValueError, "immutable store path"):
                commitments.store_root(locator)

    def test_ordinary_registry_remains_unmodified_without_fixtures(self):
        self.inputs["fixtures"] = {}
        self.assertEqual(commitments.commit_registry(self.inputs), self.inputs["registry"])


if __name__ == "__main__":
    unittest.main()

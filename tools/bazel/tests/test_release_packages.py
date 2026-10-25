"""Checks release identities exported from the Bazel source ownership catalog."""

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
from export_release_packages import DECLARATIONS, export


class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.package = {
            "name": "example", "directory": "crates/example", "version": "1.2.3",
            "edition": "2024", "license": "Apache-2.0", "license_domain": "apache-host",
        }
        for file in [*DECLARATIONS, "crates/example/BUILD.bazel"]:
            path = self.root / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("declared source: " + file + "\n")
        self.catalog = {"schema_version": 1, "packages": [self.package]}

    def test_export_needs_only_bazel_declarations_and_preserves_identity(self):
        result = export(self.root, self.catalog, ["example"])
        self.assertEqual(result["packages"]["example"], {
            key: value for key, value in self.package.items() if key != "name"
        })
        self.assertEqual(set(result["declaration_sha256"]), {*DECLARATIONS, "crates/example/BUILD.bazel"})
        for file, digest in result["declaration_sha256"].items():
            self.assertEqual(digest, hashlib.sha256((self.root / file).read_bytes()).hexdigest())
        self.assertFalse(list(self.root.rglob("Cargo.toml")))

    def test_unknown_duplicate_or_empty_selections_fail(self):
        for selection in [[], ["example", "example"], ["missing"], [1], [""]]:
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                export(self.root, self.catalog, selection)

    def test_duplicate_catalog_identities_and_directories_fail(self):
        other = deepcopy(self.package)
        with self.assertRaisesRegex(ValueError, "duplicate Bazel"):
            export(self.root, {**self.catalog, "packages": [self.package, other]}, ["example"])
        other["name"] = "other"
        with self.assertRaisesRegex(ValueError, "duplicate release package directory"):
            export(self.root, {**self.catalog, "packages": [self.package, other]}, ["example", "other"])

    def test_traversal_and_noncanonical_directories_fail_before_reading(self):
        for directory in ["/crates/example", "crates/../outside", "crates//example", "crates/./example", "crates/example/", "crates/example\\outside", "other/example"]:
            catalog = deepcopy(self.catalog)
            catalog["packages"][0]["directory"] = directory
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, "invalid release package directory"):
                export(self.root, catalog, ["example"])

    def test_missing_declarations_and_incomplete_metadata_fail(self):
        path = self.root / "crates/example/BUILD.bazel"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            export(self.root, self.catalog, ["example"])
        path.write_text("restored\n")
        for field in ["version", "edition", "license", "license_domain"]:
            catalog = deepcopy(self.catalog)
            catalog["packages"][0][field] = ""
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "incomplete"):
                export(self.root, catalog, ["example"])

    def test_changed_build_input_changes_the_retained_identity_digest(self):
        before = export(self.root, self.catalog, ["example"])
        (self.root / "crates/example/BUILD.bazel").write_text("changed declaration\n")
        after = export(self.root, self.catalog, ["example"])
        self.assertNotEqual(before["declaration_sha256"], after["declaration_sha256"])


if __name__ == "__main__":
    unittest.main()

"""Checks source catalog coverage, ownership, and metadata-only generation."""

from pathlib import Path
import tempfile
import unittest

import verify_source_catalog as verifier


class SourceCatalogTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        source = self.root / "crates/example/src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("pub fn example() {}\n")
        self.package = {
            "name": "example", "version": "0.1.0", "edition": "2024",
            "license": "Apache-2.0", "license_domain": "apache-host",
            "directory": "crates/example", "sources": ["crates/example/src/lib.rs"],
        }
        self.oracle = [{
            "name": "example", "version": "0.1.0", "license": "Apache-2.0",
            "manifest": "crates/example/Cargo.toml", "targets": [{"edition": "2024"}],
        }]

    def validate(self, packages=None):
        return verifier.validate_catalog(
            self.root,
            {"schema_version": 1, "packages": packages if packages is not None else [self.package]},
            self.oracle,
        )

    def test_exact_coverage_without_cargo_manifests(self):
        self.assertEqual(self.validate(), {"packages": 1, "sources": 1})
        self.assertFalse((self.root / "crates/example/Cargo.toml").exists())

    def test_missing_and_duplicate_packages(self):
        for packages in [[], [self.package, self.package]]:
            with self.subTest(packages=packages):
                with self.assertRaisesRegex(ValueError, "package names"):
                    self.validate(packages)

    def test_identity_and_domain_mismatch(self):
        for key, value in [("version", "0.2.0"), ("edition", "2021"), ("license_domain", "gpl-qemu")]:
            package = dict(self.package, **{key: value})
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.validate([package])

    def test_undeclared_source_fails_coverage(self):
        (self.root / "crates/example/src/added.rs").write_text("// newly owned source\n")
        with self.assertRaisesRegex(ValueError, "coverage differs"):
            self.validate()

    def test_nested_package_is_not_owned_by_parent(self):
        nested = self.root / "crates/example/frontend"
        nested.mkdir()
        (nested / "BUILD.bazel").write_text("# separate owner\n")
        (nested / "lib.rs").write_text("// nested source\n")
        self.assertEqual(self.validate()["sources"], 1)

    def test_path_escape_and_duplicate_sources(self):
        for sources in [
            ["crates/example/../outside.rs"],
            ["crates/elsewhere/lib.rs"],
            ["/outside.rs"],
            self.package["sources"] * 2,
        ]:
            with self.subTest(sources=sources):
                with self.assertRaises(ValueError):
                    self.validate([dict(self.package, sources=sources)])

    def test_symlink_escape(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        source = self.root / self.package["sources"][0]
        source.unlink()
        source.symlink_to(Path(outside.name) / "lib.rs")
        with self.assertRaisesRegex(ValueError, "escapes workspace"):
            self.validate()

    def test_metadata_generation_cannot_spawn_tools(self):
        verifier.validate_metadata_only("")
        with self.assertRaisesRegex(ValueError, "executed a build tool"):
            verifier.validate_metadata_only('{"commandArgs": ["rustc"]}')


if __name__ == "__main__":
    unittest.main()

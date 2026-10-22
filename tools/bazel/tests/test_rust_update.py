"""Checks dependency-update integrity and ownership without network access."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/update_rust.py"
spec = importlib.util.spec_from_file_location("update_rust", path)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class RustUpdateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.staged = self.root / "staged"
        self.staged.mkdir()
        self.output = self.root / "output"
        self.output.mkdir()

    def test_publication_preserves_unmanaged_files_and_removes_owned_obsolete_files(self):
        (self.output / "notes.txt").write_text("keep this\n")
        (self.output / "obsolete.bazel").write_text("old graph\n")
        (self.output / "sources.json").write_text(json.dumps({
            "schema_version": 1, "generated_files": {"obsolete.bazel": "old digest"},
        }))
        (self.staged / "BUILD.new.bazel").write_text("new graph\n")
        (self.staged / "sources.json").write_text("{}\n")

        updater.publish(self.staged, self.output)

        self.assertEqual((self.output / "notes.txt").read_text(), "keep this\n")
        self.assertEqual((self.output / "BUILD.new.bazel").read_text(), "new graph\n")
        self.assertFalse((self.output / "obsolete.bazel").exists())
        self.assertEqual(list(self.output.glob(".update-*")), [])

    def test_unmanaged_collision_and_unsafe_obsolete_paths_fail_before_writes(self):
        (self.output / "BUILD.new.bazel").write_text("human declaration\n")
        (self.staged / "BUILD.new.bazel").write_text("generated declaration\n")
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            updater.publish(self.staged, self.output)
        self.assertEqual((self.output / "BUILD.new.bazel").read_text(), "human declaration\n")

        (self.output / "sources.json").write_text(json.dumps({
            "schema_version": 1, "generated_files": {"../outside": "digest"},
        }))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            updater.publish(self.staged, self.output)

    def test_boundary_sources_require_reviewed_original_license(self):
        specification = {
            "license_domain": "permissive-protocol",
            "approved_licenses": ["MIT OR Apache-2.0"],
        }
        crate = {"name": "example", "version": "1.0.0", "license": "MIT OR Apache-2.0"}
        self.assertEqual(updater.validate_license(specification, crate), "permissive-protocol")

        for license_expression in ["Apache-2.0", "GPL-3.0-only", "MIT OR Apache-2.0 OR unknown"]:
            with self.subTest(license=license_expression):
                crate["license"] = license_expression
                with self.assertRaisesRegex(ValueError, "unreviewed protocol dependency"):
                    updater.validate_license(specification, crate)

    def test_reviewed_host_only_license_never_inherits_protocol_scope(self):
        specification = {
            "license_domain": "permissive-protocol",
            "approved_licenses": ["MIT OR Apache-2.0"],
            "host_only_licenses": ["Apache-2.0"],
        }
        crate = {"name": "ciborium", "version": "0.2.2", "license": "Apache-2.0"}
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

        # A duplicate broad approval cannot weaken the explicit restriction.
        specification["approved_licenses"].append("Apache-2.0")
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

        crate["license"] = "unreviewed"
        with self.assertRaisesRegex(ValueError, "unreviewed protocol dependency"):
            updater.validate_license(specification, crate)

    def test_archive_must_match_both_resolved_locks(self):
        archive = self.root / "cargo-home/registry/cache/example/example-1.0.0.crate"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"source archive")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "spliced").mkdir()
        (self.root / "spliced/Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{checksum}"\n'
        )
        (self.root / "context.json").write_text(json.dumps({"crates": {"example": {
            "name": "example", "version": "1.0.0",
            "repository": {"Http": {"url": "https://static.crates.io/example.crate", "sha256": "wrong"}},
        }}}))

        with self.assertRaisesRegex(ValueError, "checksum disagrees"):
            updater.prepare_sources({"license_domain": "apache-host"}, self.root, "example", self.staged)

        self.assertEqual(list(self.staged.iterdir()), [])

    def test_generated_rules_and_source_inventory_retain_host_only_scope(self):
        archive = self.root / "cargo-home/registry/cache/example/example-1.0.0.crate"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"source archive")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "spliced").mkdir()
        (self.root / "spliced/Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{checksum}"\n'
        )
        (self.root / "context.json").write_text(json.dumps({
            "crates": {"example": {
                "name": "example", "version": "1.0.0", "license": "Apache-2.0",
                "library_target_name": "example",
                "repository": {"Http": {"url": "https://static.crates.io/example.crate", "sha256": checksum}},
            }},
            "direct_deps": ["example"],
        }))
        (self.root / "rendered").mkdir()
        (self.root / "rendered/BUILD.example-1.0.0.bazel").write_text('rust_library(\n    tags = [\n    ],\n)\n')
        (self.root / "config.json").write_text("{}\n")
        specification = {"license_domain": "permissive-protocol", "host_only_licenses": ["Apache-2.0"]}

        sources = updater.prepare_sources(specification, self.root, "example", self.staged)

        self.assertEqual(sources["example__example-1.0.0"]["license_domain"], "apache-host")
        rendered = (self.staged / "BUILD.example-1.0.0.bazel").read_text()
        self.assertIn('"aos-license:apache-host"', rendered)
        self.assertNotIn('"aos-license:permissive-protocol"', rendered)


if __name__ == "__main__":
    unittest.main()

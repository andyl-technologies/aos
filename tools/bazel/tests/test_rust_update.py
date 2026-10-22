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


if __name__ == "__main__":
    unittest.main()

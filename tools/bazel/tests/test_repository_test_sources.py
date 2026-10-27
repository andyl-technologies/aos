"""Keeps recursive source audits complete under Bazel's symlinked inputs."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "metadata/copy_repository_test_sources.py"
spec = importlib.util.spec_from_file_location("copy_repository_test_sources", path)
copier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(copier)


class RepositoryTestSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.manifest = self.root / "manifest.json"
        self.output = self.root / "output"
        self.bytes = b"declared production source\n"
        (self.source / "actual.rs").write_bytes(self.bytes)
        self.files = {"nested/lib.rs": {
            "sha256": hashlib.sha256(self.bytes).hexdigest(), "size": len(self.bytes),
        }}
        (self.source / "nested").mkdir()
        (self.source / "nested/lib.rs").symlink_to(self.source / "actual.rs")

    def copy(self):
        self.manifest.write_text(json.dumps({"schema_version": 1, "files": self.files}))
        copier.materialize(self.source, self.manifest, self.output)

    def test_symlinked_inputs_become_regular_files_with_identical_bytes(self):
        self.copy()

        target = self.output / "nested/lib.rs"
        self.assertEqual(target.read_bytes(), self.bytes)
        self.assertFalse(target.is_symlink())
        self.assertEqual([str(p.relative_to(self.output)) for p in self.output.rglob("*") if p.is_file()], ["nested/lib.rs"])

    def test_content_drift_is_rejected(self):
        (self.source / "actual.rs").write_bytes(b"different production source")

        with self.assertRaisesRegex(ValueError, "content differs"):
            self.copy()

    def test_suffixed_build_files_retain_their_audited_names(self):
        nested = self.source / "nested/BUILD.bazel.aos-source"
        nested.write_bytes(self.bytes)
        self.files = {"nested/BUILD.bazel": {
            "sha256": hashlib.sha256(self.bytes).hexdigest(), "size": len(self.bytes),
        }}
        self.manifest.write_text(json.dumps({"schema_version": 1, "files": self.files}))

        copier.materialize(self.source, self.manifest, self.output, ".aos-source")

        self.assertEqual((self.output / "nested/BUILD.bazel").read_bytes(), self.bytes)

    def test_source_suffix_cannot_change_directories(self):
        with self.assertRaisesRegex(ValueError, "must not contain separators"):
            copier.materialize(self.source, self.manifest, self.output, "/outside")

    def test_audited_executable_mode_is_preserved(self):
        self.files["nested/lib.rs"]["executable"] = True

        self.copy()

        self.assertEqual((self.output / "nested/lib.rs").stat().st_mode & 0o777, 0o755)

    def test_invalid_executable_flag_is_rejected(self):
        self.files["nested/lib.rs"]["executable"] = "yes"

        with self.assertRaisesRegex(ValueError, "invalid repository source executable flag"):
            self.copy()

    def test_incorrect_size_is_rejected_even_with_matching_digest(self):
        self.files["nested/lib.rs"]["size"] += 1

        with self.assertRaisesRegex(ValueError, "content differs"):
            self.copy()

    def test_ambiguous_or_escaping_paths_are_rejected(self):
        for name in ["../outside.rs", "/absolute.rs", "nested/../actual.rs", "nested//lib.rs", "./actual.rs"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as output:
                self.output = Path(output)
                self.files = {name: {"sha256": hashlib.sha256(self.bytes).hexdigest(), "size": len(self.bytes)}}
                with self.assertRaisesRegex(ValueError, "ambiguous repository source path"):
                    self.copy()

    def test_empty_source_inventory_is_rejected(self):
        self.files = {}

        with self.assertRaisesRegex(ValueError, "must contain files"):
            self.copy()

    def test_existing_output_contents_are_rejected(self):
        self.output.mkdir()
        (self.output / "stale.rs").write_text("stale source")

        with self.assertRaisesRegex(ValueError, "output must be empty"):
            self.copy()

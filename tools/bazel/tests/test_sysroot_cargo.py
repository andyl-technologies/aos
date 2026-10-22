"""Checks the read-only standard-library metadata adapter's command boundary."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "toolchains"))
from sysroot_cargo import metadata, metadata_file


class SysrootMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "library"
        self.library.mkdir()
        (self.library / "Cargo.toml").touch()
        self.prefix = ["--metadata-directory", str(self.root / "metadata"), "--library", str(self.library)]
        self.arguments = ["metadata", "--manifest-path", str(self.library / "Cargo.toml"),
                          "--format-version", "1", "--filter-platform", "aarch64-unknown-linux-gnu"]

    def test_supported_request_returns_only_prepared_target_metadata(self):
        result = metadata_file(self.prefix + self.arguments + ["-Zlockfile-path", "-Zunstable-options"])
        self.assertEqual(result, self.root / "metadata/aarch64-unknown-linux-gnu.json")

    def test_toolchain_source_symlink_is_allowed(self):
        alias = self.root / "rust-src"
        alias.symlink_to(self.library, target_is_directory=True)
        arguments = self.arguments.copy()
        arguments[2] = str(alias / "Cargo.toml")
        self.assertEqual(metadata_file(self.prefix + arguments), self.root / "metadata/aarch64-unknown-linux-gnu.json")

    def test_first_party_manifest_is_rejected(self):
        manifest = self.root / "Cargo.toml"
        manifest.touch()
        arguments = self.arguments.copy()
        arguments[2] = str(manifest)
        with self.assertRaisesRegex(ValueError, "disabled in first-party"):
            metadata_file(self.prefix + arguments)

    def test_library_paths_and_dependency_ids_follow_the_requested_source_alias(self):
        directory = self.root / "metadata"
        directory.mkdir()
        (directory / "aarch64-unknown-linux-gnu.json").write_text(json.dumps({
            "workspace_root": "/prepared/library",
            "packages": [{"manifest_path": "/prepared/library/core/Cargo.toml", "id": "path+file:///prepared/library/core#0.0.0"}],
        }))
        alias = self.root / "cross-library"
        alias.symlink_to(self.library, target_is_directory=True)
        arguments = self.arguments.copy()
        arguments[2] = str(alias / "Cargo.toml")

        document = json.loads(metadata(self.prefix + arguments))

        self.assertEqual(document["workspace_root"], str(alias))
        self.assertEqual(document["packages"][0]["manifest_path"], str(alias / "core/Cargo.toml"))
        self.assertEqual(document["packages"][0]["id"], "path+file://" + str(alias / "core") + "#0.0.0")

    def test_compilation_and_changed_features_are_rejected(self):
        for arguments in [["build"], self.arguments + ["--all-features"], self.arguments + ["--config", "network=true"]]:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    metadata_file(self.prefix + arguments)


if __name__ == "__main__":
    unittest.main()

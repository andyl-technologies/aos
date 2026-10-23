"""Checks package identity parity independently of Cargo execution."""

from pathlib import Path
import tempfile
import unittest

from verify_package_metadata import verify


class PackageMetadataTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        package = self.root / "crates/example"
        package.mkdir(parents=True)
        (package.parent / "Cargo.toml").write_text(
            '[workspace.package]\nlicense = "Apache-2.0"\nauthors = ["One", "Two"]\n'
        )
        (package / "Cargo.toml").write_text(
            '[package]\nname = "example"\nversion = "2.3.4-rc.5+build.6"\n'
            'edition = "2024"\nlicense.workspace = true\nauthors.workspace = true\n'
        )
        self.environment = {
            "CARGO_PKG_NAME": "example", "CARGO_PKG_VERSION": "2.3.4-rc.5+build.6",
            "CARGO_PKG_VERSION_MAJOR": "2", "CARGO_PKG_VERSION_MINOR": "3",
            "CARGO_PKG_VERSION_PATCH": "4", "CARGO_PKG_VERSION_PRE": "rc.5",
            "CARGO_PKG_AUTHORS": "One:Two", "CARGO_PKG_LICENSE": "Apache-2.0",
            **{"CARGO_PKG_" + name: "" for name in [
                "DESCRIPTION", "HOMEPAGE", "REPOSITORY", "LICENSE_FILE", "README", "RUST_VERSION",
            ]},
        }

    def target(self, kind="rust_library"):
        return {
            "label": "//crates/example:" + kind, "kind": kind,
            "edition": "2024", "version": "2.3.4-rc.5+build.6",
            "rustc_env": dict(self.environment),
        }

    def test_inherited_fields_and_semver_match_all_compiled_target_kinds(self):
        targets = [self.target(kind) for kind in ["rust_library", "rust_binary", "rust_test", "rust_proc_macro", "rust_shared_library"]]
        result = verify(self.root, [{"configured_targets": targets}])
        self.assertEqual(len(result["targets"]), 5)
        self.assertEqual(
            result["targets"][targets[0]["label"]]["environment"], self.environment,
        )

    def test_default_version_and_missing_or_overridden_environment_fail(self):
        for changed in ["version", *self.environment]:
            with self.subTest(field=changed):
                target = self.target("rust_test")
                if changed == "version":
                    target["version"] = "0.0.0"
                else:
                    target["rustc_env"].pop(changed)
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    verify(self.root, [{"configured_targets": [target]}])

    def test_empty_or_external_only_inventory_is_not_parity_evidence(self):
        target = self.target()
        target["label"] = "@@third_party//:library"
        with self.assertRaisesRegex(ValueError, "did not compare any Rust targets"):
            verify(self.root, [{"configured_targets": [target]}])

    def test_shared_library_metadata_is_checked(self):
        target = self.target("rust_shared_library")
        target["rustc_env"]["CARGO_PKG_NAME"] = "incorrect-library"

        with self.assertRaisesRegex(ValueError, "identity differs"):
            verify(self.root, [{"configured_targets": [target]}])


if __name__ == "__main__":
    unittest.main()

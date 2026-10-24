"""Checks that editor-oracle selection preserves the compiled default view."""

from pathlib import Path
import tempfile
import tomllib
import unittest

from select_cargo_editor import select


class CargoEditorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "Cargo.toml"
        self.source = '''[package]
name = "example"
version = "1.0.0"
edition = "2024"

[features]
default = []
test-support = []

[dependencies]
serde = { version = "1", features = ["derive"] }

[[test]]
name = "gated"
required-features = ["test-support"]

[[test]]
name = "explicit"
path = "tests/custom.rs"
'''
        self.manifest.write_text(self.source)
        for name in ["auto.rs", "gated.rs", "custom.rs", "nested/main.rs"]:
            path = self.root / "tests" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// Original test source.\n")
        self.targets = [
            {"name": name, "src_path": str(self.root / "tests" / path), "kind": ["test"]}
            for name, path in [("auto", "auto.rs"), ("gated", "gated.rs"), ("explicit", "custom.rs"), ("nested", "nested/main.rs")]
        ]

    def test_disabled_targets_are_omitted_without_losing_automatic_or_explicit_tests(self):
        before = {path: path.read_bytes() for path in (self.root / "tests").rglob("*.rs")}

        selected, omitted = select(self.manifest, {"gated"}, self.targets)

        self.assertEqual(omitted, {"gated"})
        self.assertEqual(set(selected), {"auto", "explicit", "nested"})
        self.assertEqual(selected["explicit"]["path"], "tests/custom.rs")
        manifest = tomllib.loads(self.manifest.read_text())
        self.assertFalse(manifest["package"]["autotests"])
        self.assertEqual(manifest["dependencies"], tomllib.loads(self.source)["dependencies"])
        self.assertEqual(manifest["features"], tomllib.loads(self.source)["features"])
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_enabled_required_feature_and_unconditional_tests_cannot_be_omitted(self):
        for source in [
            self.source.replace('default = []', 'default = ["test-support"]'),
            self.source.replace('required-features = ["test-support"]', ''),
        ]:
            with self.subTest(source=source):
                self.manifest.write_text(source)
                with self.assertRaisesRegex(ValueError, "default-enabled"):
                    select(self.manifest, {"gated"}, self.targets)
                self.assertEqual(self.manifest.read_text(), source)

    def test_disabled_automatic_discovery_is_preserved(self):
        self.manifest.write_text(self.source.replace('[package]', '[package]\nautotests = false'))

        targets = [target for target in self.targets if target["name"] in {"explicit", "gated"}]
        selected, omitted = select(self.manifest, {"gated"}, targets)

        self.assertEqual(set(selected), {"explicit"})
        self.assertEqual(omitted, {"gated"})

    def bin_fixture(self):
        source = self.source.replace('default = []', 'default = ["test-support"]') + '''
[[bin]]
name = "boot-command"
path = "src/bin/boot-command.rs"
required-features = ["test-support"]

[[bin]]
name = "custom"
path = "src/custom.rs"
'''
        self.manifest.write_text(source)
        targets = list(self.targets)
        for name, path in [("boot-command", "src/bin/boot-command.rs"),
                           ("custom", "src/custom.rs"), ("auto", "src/bin/auto.rs")]:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("fn main() {}\n")
            targets.append({"name": name, "src_path": str(file), "kind": ["bin"]})
        return source, targets

    def test_minimal_profile_omits_gated_bins_and_preserves_tests_and_sources(self):
        source, targets = self.bin_fixture()
        before = {path: path.read_bytes() for path in self.root.rglob("*.rs")}

        selected, omitted = select(
            self.manifest, {"boot-command"}, targets, kind="bin", default_features=False,
        )

        self.assertEqual(omitted, {"boot-command"})
        self.assertEqual(set(selected), {"custom", "auto"})
        actual = tomllib.loads(self.manifest.read_text())
        original = tomllib.loads(source)
        self.assertFalse(actual["package"]["autobins"])
        for field in ["test", "features", "dependencies"]:
            self.assertEqual(actual[field], original[field])
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_enabled_or_unconditional_bins_cannot_be_omitted(self):
        source, targets = self.bin_fixture()
        for candidate, defaults in [
            (source, True),
            (source.replace('required-features = ["test-support"]', ''), False),
        ]:
            with self.subTest(defaults=defaults):
                self.manifest.write_text(candidate)

                with self.assertRaisesRegex(ValueError, "default-enabled"):
                    select(self.manifest, {"boot-command"}, targets, kind="bin", default_features=defaults)

                self.assertEqual(self.manifest.read_text(), candidate)


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

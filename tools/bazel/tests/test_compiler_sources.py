"""Rejects source drift and incomplete compiler comparison snapshots."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from verify_compiler_sources import compare


class CompilerSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bazel = self.root / "bazel"
        self.cargo = self.root / "cargo"
        self.names = ["crates/example/src/lib.rs", "api/example.proto"]
        self.inventory = {"schema_version": 1, "source_files": self.names.copy()}
        for root in [self.bazel, self.cargo]:
            for name in self.names:
                source = root / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(b"actual source\n")

    def compare(self):
        return compare(self.inventory, self.bazel, self.cargo)

    def test_retains_all_selected_rust_and_protocol_input_hashes(self):
        actual = self.compare()

        self.assertEqual(actual["sources_sha256"], {
            name: hashlib.sha256(b"actual source\n").hexdigest() for name in self.names
        })

    def test_unselected_checkout_and_metadata_files_are_not_compiler_evidence(self):
        self.inventory["source_files"].extend(["README.md", "crates/example/Cargo.toml"])
        (self.cargo / "README.md").write_text("only in Cargo's source snapshot")

        self.assertEqual(set(self.compare()["sources_sha256"]), set(self.names))

    def test_changed_rust_or_protocol_source_fails(self):
        for name in self.names:
            with self.subTest(name=name):
                source = self.cargo / name
                source.write_bytes(b"different source\n")
                with self.assertRaisesRegex(ValueError, "source bytes differ"):
                    self.compare()
                source.write_bytes(b"actual source\n")

    def test_missing_input_on_either_compiler_side_fails(self):
        for root in [self.bazel, self.cargo]:
            with self.subTest(root=root):
                source = root / self.names[0]
                source.unlink()
                with self.assertRaisesRegex(ValueError, "missing compiler source"):
                    self.compare()
                source.write_bytes(b"actual source\n")

    def test_empty_compiler_selection_fails(self):
        self.inventory["source_files"] = ["README.md", "crates/example/Cargo.toml"]

        with self.assertRaisesRegex(ValueError, "no selected first-party"):
            self.compare()

    def test_malformed_duplicate_or_noncanonical_inventory_paths_fail(self):
        variants = [None, [7], [self.names[0], self.names[0]], ["../outside.rs"],
                    ["/crates/outside.rs"], ["crates//example.rs"], ["crates/./example.rs"],
                    ["crates\\example.rs"], [""]]
        for names in variants:
            with self.subTest(names=names):
                self.inventory["source_files"] = names
                with self.assertRaises(ValueError):
                    self.compare()

    def test_symlink_escape_from_declared_source_root_fails(self):
        outside = self.root / "outside.rs"
        outside.write_bytes(b"actual source\n")
        source = self.bazel / self.names[0]
        source.unlink()
        source.symlink_to(outside)

        with self.assertRaisesRegex(ValueError, "escapes declared root"):
            self.compare()

    def test_unknown_inventory_schema_fails(self):
        self.inventory["schema_version"] = 2

        with self.assertRaisesRegex(ValueError, "unsupported compiler source inventory"):
            self.compare()


if __name__ == "__main__":
    unittest.main()

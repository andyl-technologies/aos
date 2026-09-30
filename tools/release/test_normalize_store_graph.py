"""Regression tests for preserving NAR identities during catalog repair."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("normalize_store_graph", Path(__file__).with_name("normalize-store-graph.py"))
REPAIR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPAIR)


class StoreGraphRepairTests(unittest.TestCase):
    def test_known_nix_hash_vector_and_dependency_preservation(self):
        source = ("nar:sha256:sha256-k4pdPVojNEE3FS5PXPj3+5/7V2YIDYqU9siTdpDW9qs=:4896\n"
                  "  ia:sha256:123abc\n")
        expected = ("nar:sha256:1aznss87d4y8ysa8l388crbzp7zvyzw5qkrf2lvl2d13b8ymv2lk:4896\n"
                    "  ia:sha256:123abc\n")

        self.assertEqual(REPAIR.normalize_record(source), expected)
        self.assertEqual(REPAIR.normalize_record(expected), expected)

    def test_rejects_invalid_or_truncated_digests(self):
        for digest in ("sha256-!!!", "sha256-YQ==", "z" * 52, "0" * 51):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                REPAIR.normalize_record(f"nar:sha256:{digest}:1\n")

    def test_validation_failure_does_not_partially_write_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory)
            shard = registry / "store" / "00"
            shard.mkdir(parents=True)
            valid = shard / "00a"
            original = "nar:sha256:sha256-" + "A" * 43 + "=:1\n"
            valid.write_text(original)
            (shard / "00b").write_text("nar:sha256:broken:1\n")

            with self.assertRaises(ValueError):
                REPAIR.normalize_tree(registry, write=True)

            self.assertEqual(valid.read_text(), original)


if __name__ == "__main__":
    unittest.main()

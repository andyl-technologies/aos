"""Checks source attribution without dropping synthetic analyzer diagnostics."""

from pathlib import Path
import tempfile
import unittest

from normalize_editor_diagnostics import normalize
from verify_family_editor import diagnostics


class DiagnosticContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "analyzer-output.txt"
        self.output = self.root / "diagnostics.csv"

    def test_synthetic_rows_retain_body_ownership_types_and_multiplicity(self):
        self.source.write_text(
            'processing: engine::first (/build/workspace/crates/engine/src/lib.rs 10..80)\n'
            'synthetic,,,type,"Option<{unknown}>"\n' * 2
            + 'processing: dependency::next (/build/source/crates/dependency/src/lib.rs 90..150)\n'
            + 'synthetic,,,type,"{unknown}"\n'
        )

        self.assertEqual(normalize(self.source, self.output), 3)
        rows = diagnostics(self.output)

        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "crates/dependency/src/lib.rs")
        self.assertEqual(rows[1], rows[2])
        self.assertEqual(rows[1], ["crates/engine/src/lib.rs", "body-byte:10", "body-byte:80",
                                   "synthetic-type", "Option<{unknown}>"])

    def test_ordinary_types_and_mismatches_survive_verbose_messages(self):
        self.source.write_text(
            'processing: engine::first (/build/crates/engine/src/lib.rs 10..80)\n'
            '/build/crates/engine/src/lib.rs 1:0-1:2: Unknown type\n'
            '/build/crates/engine/src/lib.rs,1:0,1:2,type,"{unknown}"\n'
            '/build/crates/engine/src/lib.rs,2:0,2:2,mismatch,"u32","()"\n'
            'engine::first: 2 exprs, 1 unknown, 0 partial\n'
        )

        self.assertEqual(normalize(self.source, self.output), 2)

        self.assertEqual([row[3] for row in diagnostics(self.output)], ["type", "mismatch"])

    def test_missing_or_unlocated_body_cannot_reuse_a_previous_context(self):
        for prefix in ["", 'processing: engine::first (/build/crates/engine/src/lib.rs 10..80)\n'
                       'processing: engine::unlocated\n']:
            with self.subTest(prefix=prefix):
                self.source.write_text(prefix + 'synthetic,,,type,"{unknown}"\n')
                with self.assertRaisesRegex(ValueError, "lacks its source body"):
                    normalize(self.source, self.output)

    def test_invalid_source_body_and_malformed_diagnostic_fail(self):
        for body in ["/build/external/src/lib.rs 10..80", "/build/crates/engine/src/lib.rs 80..10"]:
            with self.subTest(body=body):
                self.source.write_text(f'processing: engine::first ({body})\nsynthetic,,,type,"{{unknown}}"\n')
                with self.assertRaisesRegex(ValueError, "outside first-party sources"):
                    normalize(self.source, self.output)
        self.source.write_text('synthetic,,,type\n')
        with self.assertRaisesRegex(ValueError, "malformed"):
            normalize(self.source, self.output)

    def test_statistics_reject_lost_diagnostics_and_mismatch_rows(self):
        log = self.root / "analysis.log"
        log.write_text('exprs: 10, ??ty: 1 (10%), ?ty: 0 (0%), !ty: 1\n'
                       'pats: 2, ??ty: 0 (0%), ?ty: 0 (0%), !ty: 0\n')
        self.source.write_text('/build/crates/engine/src/lib.rs,1:0,1:2,type,"{unknown}"\n')

        with self.assertRaisesRegex(ValueError, "differ from statistics"):
            normalize(self.source, self.output, log)
        with self.source.open("a") as stream:
            stream.write('/build/crates/engine/src/lib.rs,2:0,2:2,mismatch,"u32","()"\n')

        self.assertEqual(normalize(self.source, self.output, log), 2)


if __name__ == "__main__":
    unittest.main()

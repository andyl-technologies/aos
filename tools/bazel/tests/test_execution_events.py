"""Checks parsing of Bazel's successive JSON execution records."""

import json
from pathlib import Path
import tempfile
import unittest

from verify_cache import execution_events


class ExecutionEventTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.build = Path(temporary.name)
        (self.build / "evidence").mkdir()
        self.log = self.build / "evidence/execution.json"

    def test_adjacent_records_and_intervening_whitespace_are_preserved(self):
        expected = [{"mnemonic": "Rustc", "inputs": [{"path": "a b.rs"}]}, {"mnemonic": "TestRunner"}]
        for separator in ["", "\n  \t", "\r\n"]:
            with self.subTest(separator=separator):
                self.log.write_text(" \n" + separator.join(map(json.dumps, expected)) + "\n \t")

                self.assertEqual(execution_events(self.build), expected)

    def test_empty_or_whitespace_only_stream_has_no_events(self):
        for contents in ["", "\n \r\t"]:
            with self.subTest(contents=contents):
                self.log.write_text(contents)

                self.assertEqual(execution_events(self.build), [])

    def test_malformed_trailing_record_fails(self):
        self.log.write_text('{"mnemonic": "Rustc"}\n{"unfinished":')

        with self.assertRaises(json.JSONDecodeError):
            execution_events(self.build)


if __name__ == "__main__":
    unittest.main()

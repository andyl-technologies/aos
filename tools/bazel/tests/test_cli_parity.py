"""Exercises CLI execution evidence independently of successful compilation."""

import json
from pathlib import Path
import tempfile
import unittest

from verify_cli import CLI_PATH, cargo_results


class CargoExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.messages = Path(self.temporary.name) / "messages.jsonl"
        self.messages.write_text(json.dumps({
            "reason": "compiler-artifact",
            "profile": {"test": True},
            "manifest_path": "/build/source/" + CLI_PATH + "/Cargo.toml",
            "executable": "/retained/test-binaries/aos_cli-123",
            "target": {"kind": ["lib"], "name": "aos_cli"},
        }) + "\n")
        self.log = """     Running unittests src/lib.rs (/build/target/deps/aos_cli-123)

running 1 test
test cli::parses ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aos_cli

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""

    def test_binds_execution_to_retained_artifact(self):
        self.assertEqual(cargo_results(self.log, self.messages), {
            "//" + CLI_PATH + ":unit": ["cli::parses"],
        })

    def test_rejects_failed_case(self):
        log = self.log.replace("cli::parses ... ok", "cli::parses ... FAILED")
        log = log.replace("ok. 1 passed; 0 failed", "FAILED. 0 passed; 1 failed")
        with self.assertRaisesRegex(ValueError, "did not pass"):
            cargo_results(log, self.messages)

    def test_rejects_ignored_case(self):
        log = self.log.replace("cli::parses ... ok", "cli::parses ... ignored")
        log = log.replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored")
        with self.assertRaisesRegex(ValueError, "ignored"):
            cargo_results(log, self.messages)

    def test_rejects_missing_execution(self):
        with self.assertRaisesRegex(ValueError, "inventories differ"):
            cargo_results("", self.messages)

    def test_rejects_unknown_artifact(self):
        with self.assertRaisesRegex(ValueError, "unknown or duplicate"):
            cargo_results(self.log.replace("deps/aos_cli-123", "deps/unrelated-123"), self.messages)

    def test_rejects_case_summary_disagreement(self):
        with self.assertRaisesRegex(ValueError, "differ from their summary"):
            cargo_results(self.log.replace("ok. 1 passed", "ok. 2 passed"), self.messages)

    def test_rejects_new_doctest_until_declared(self):
        log = self.log.replace("running 0 tests", "running 1 test\ntest src/lib.rs - parse (line 10) ... ok")
        # Change only the final rustdoc summary.
        head, tail = log.split("Doc-tests aos_cli")
        log = head + "Doc-tests aos_cli" + tail.replace("ok. 0 passed", "ok. 1 passed")
        with self.assertRaisesRegex(ValueError, "doctest inventory changed"):
            cargo_results(log, self.messages)


if __name__ == "__main__":
    unittest.main()

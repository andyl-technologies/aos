"""Checks transparent compiler delegation and concurrent trace integrity."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


WRAPPER = Path(__file__).with_name("trace_cargo_rustc.py")


class CompilerTraceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trace = self.root / "compiler.jsonl"
        self.environment = {
            **os.environ,
            "AOS_CARGO_RUSTC_TRACE": str(self.trace),
            "CARGO_PKG_NAME": "example",
            "CARGO_FEATURE_NATIVE": "1",
            "OUT_DIR": "/build/generated",
            "UNRELATED_SECRET": "must remain absent",
        }

    def invoke(self, program, *arguments, compiler=sys.executable):
        return subprocess.run(
            [sys.executable, str(WRAPPER), compiler, "-c", program, *arguments],
            cwd=self.root, env=self.environment, capture_output=True, text=True,
        )

    def test_preserves_arguments_streams_and_exit_status(self):
        program = "import json, sys; print(json.dumps(sys.argv[1:])); print('diagnostic', file=sys.stderr); sys.exit(37)"
        arguments = ['feature="native"', "space and 'quotes'", "line\nbreak"]
        result = self.invoke(program, *arguments)

        self.assertEqual(result.returncode, 37)
        self.assertEqual(json.loads(result.stdout), arguments)
        self.assertEqual(result.stderr, "diagnostic\n")
        record = json.loads(self.trace.read_text())
        self.assertEqual(record["arguments"], [sys.executable, "-c", program, *arguments])
        self.assertEqual(record["directory"], str(self.root))
        self.assertEqual(record["environment"]["CARGO_PKG_NAME"], "example")
        self.assertEqual(record["environment"]["CARGO_FEATURE_NATIVE"], "1")
        self.assertEqual(record["environment"]["OUT_DIR"], "/build/generated")
        self.assertNotIn("UNRELATED_SECRET", record["environment"])
        self.assertNotIn("must remain absent", self.trace.read_text())

    def test_resolves_compiler_from_cargos_path(self):
        self.environment["PATH"] = str(Path(sys.executable).parent)
        compiler = Path(sys.executable).name
        result = self.invoke("print('compiler ran')", compiler=compiler)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "compiler ran\n")
        self.assertEqual(json.loads(self.trace.read_text())["arguments"][0], compiler)

    def test_concurrent_compilers_append_complete_distinct_records(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda number: self.invoke("pass", str(number)), range(24)))

        self.assertTrue(all(result.returncode == 0 for result in results))
        records = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual(len(records), 24)
        self.assertEqual({record["arguments"][-1] for record in records}, {str(number) for number in range(24)})

    def test_trace_failure_does_not_run_an_unrecorded_compiler(self):
        self.environment["AOS_CARGO_RUSTC_TRACE"] = str(self.root / "absent" / "trace")
        result = self.invoke("print('compiler ran')")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main()

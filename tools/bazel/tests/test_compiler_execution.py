"""Rejects incomplete execution evidence and undeclared compiler invocations."""

import json
from pathlib import Path
import tempfile
import unittest

from inspect_compiler_execution import compilation_inventory, inspect, parse_execution_trace


def execution(pid, executable, arguments, result="0"):
    return f"{pid} execve({json.dumps(executable)}, {json.dumps(arguments)}, 0x123 /* 3 vars */) = {result}\n"


class ExecutionTraceTests(unittest.TestCase):
    def test_concurrent_resumption_preserves_process_and_arguments(self):
        first = execution(10, "/compiler", ["compiler", 'feature="quoted,)"'])
        second = execution(20, "/linker", ["linker", "-o", "binary"])
        trace = first.removesuffix(" = 0\n") + " <unfinished ...>\n"
        trace += second.removesuffix(" = 0\n") + " <unfinished ...>\n"
        trace += "20 <... execve resumed> = 0\n10 <... execve resumed> = 0\n"

        parsed = parse_execution_trace(trace)

        self.assertEqual([record["pid"] for record in parsed["executions"]], [20, 10])
        self.assertEqual(parsed["executions"][1]["arguments"], ["compiler", 'feature="quoted,)"'])

    def test_failed_path_lookup_is_not_successful_execution(self):
        trace = execution(10, "/missing", ["compiler"], "-1 ENOENT (No such file or directory)")
        trace += execution(10, "/compiler", ["compiler", "--version"])

        parsed = parse_execution_trace(trace)

        self.assertEqual(parsed["failed_exec_attempts"], 1)
        self.assertEqual(len(parsed["executions"]), 1)

    def test_partial_abbreviated_and_unknown_records_fail_closed(self):
        complete = execution(10, "/compiler", ["compiler", "source.rs"])
        invalid = [
            "", complete.rstrip(), "10 execve( <unfinished ...>\n",
            complete + "109 ???( <detached ...>\n",
            complete + "109 ???( <unfinished ...>\n",
            "10 <... execve resumed>) = 0\n",
            complete.replace('["compiler", "source.rs"]', "[...]"),
            complete.replace('["compiler", "source.rs"]', '["compiler", 3]'),
            complete.replace("execve(", "execveat("),
            complete.replace("0x123 /* 3 vars */", "unrecognized"),
            complete.replace(" = 0", " = ?"),
            complete.replace(" = 0", " = -1 unknown"),
            complete.replace('["compiler", "source.rs"]', "[...]").replace(" = 0", " = -1 ENOENT (No such file or directory)"),
            complete.removesuffix(" = 0\n") + " <unfinished ...>\n" + complete,
        ]
        for trace in invalid:
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                parse_execution_trace(trace)

    def test_requested_command_scope_retains_undecoded_tasks(self):
        complete = execution(10, "/compiler", ["compiler", "source.rs"])
        unresolved = "109 ???( <detached ...>\n"

        report = parse_execution_trace(complete + unresolved, retain_unresolved_tasks=True)

        self.assertEqual(len(report["executions"]), 1)
        self.assertEqual(report["unresolved_task_records"], [
            {"pid": 109, "record": "???( <detached ...>"},
        ])
        with self.assertRaises(ValueError):
            parse_execution_trace(unresolved, retain_unresolved_tasks=True)
        with self.assertRaises(ValueError):
            parse_execution_trace(complete.removesuffix(" = 0\n") + " <unfinished ...>\n"
                                  + "10 ???( <detached ...>\n", retain_unresolved_tasks=True)


class CompilerInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.trace = root / "exec.log"
        self.requested = root / "requested.jsonl"
        self.rustc, self.gcc, self.linker = [root / name for name in ["rustc.unwrapped", "gcc", "ld"]]
        for tool in [self.rustc, self.gcc, self.linker]:
            tool.write_bytes(b"declared test tool")
        self.arguments = ["--crate-name", "demo", "src/lib.rs", "--crate-type", "rlib"]
        self.requested.write_text(json.dumps({
            "schema_version": 1, "directory": "/fixture/crates/demo",
            "arguments": ["rustc"] + self.arguments,
        }) + "\n")
        self.valid = execution(10, str(self.rustc), [str(self.rustc)] + self.arguments)
        self.valid += execution(11, str(self.gcc), ["gcc", "-o", "binary"])
        self.valid += execution(12, str(self.linker), ["ld", "-o", "binary"])
        self.trace.write_text(self.valid)

    def inspect(self):
        return inspect(self.trace, self.requested, self.rustc, self.gcc, self.linker)

    def test_only_observed_noncompiling_direct_queries_are_admitted(self):
        self.trace.write_text(self.valid + execution(20, str(self.rustc), ["rustc", "--version"]))

        report = self.inspect()

        self.assertEqual(report["requested_invocations"], 1)
        self.assertEqual(report["compiler_invocations"], 2)
        self.assertEqual(report["first_party_units"][0]["source"], "crates/demo/src/lib.rs")
        self.assertEqual(report["direct_version_queries"], [{"arguments": ["--version"], "count": 1}])

    def test_extra_compilation_or_version_flags_are_rejected(self):
        for arguments in [["other.rs"], ["--version", "--unknown"], self.arguments]:
            with self.subTest(arguments=arguments):
                self.trace.write_text(self.valid + execution(20, str(self.rustc), ["rustc"] + arguments))
                with self.assertRaisesRegex(ValueError, "requested compiler invocations differ"):
                    self.inspect()

    def test_missing_compiler_or_linker_is_rejected(self):
        for missing in [str(self.rustc), str(self.gcc), str(self.linker)]:
            with self.subTest(missing=missing):
                self.trace.write_text("\n".join(line for line in self.valid.splitlines() if missing not in line) + "\n")
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_unresolved_tasks_do_not_satisfy_missing_compiler_requests(self):
        self.trace.write_text(self.valid + "109 ???( <detached ...>\n")

        report = inspect(self.trace, self.requested, self.rustc, self.gcc, self.linker,
                         retain_unresolved_tasks=True)

        self.assertFalse(report["execution_capture"]["complete"])
        self.requested.write_text(self.requested.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "requested compiler invocations differ"):
            inspect(self.trace, self.requested, self.rustc, self.gcc, self.linker,
                    retain_unresolved_tasks=True)


class CompilationInventoryTests(unittest.TestCase):
    def request(self, source="src/lib.rs"):
        return {"schema_version": 1, "directory": "/fixture/crates/demo",
                "arguments": ["rustc", source], "environment": {"CARGO_PKG_VERSION": "1.0.0"}}

    def test_order_is_immaterial_but_duplicate_requests_remain_visible(self):
        first, second = self.request(), self.request("src/main.rs")
        self.assertEqual(compilation_inventory([first, second]), compilation_inventory([second, first]))
        self.assertNotEqual(compilation_inventory([first, second]), compilation_inventory([first, first, second]))
        self.assertEqual(compilation_inventory([first, first])["units"], 2)

    def test_queries_do_not_replace_source_requests(self):
        query = {"schema_version": 1, "arguments": ["rustc", "--print=cfg"]}
        self.assertEqual(compilation_inventory([self.request(), query]), compilation_inventory([self.request()]))
        with self.assertRaisesRegex(ValueError, "no source"):
            compilation_inventory([query])

    def test_arguments_directories_and_captured_metadata_are_bound(self):
        original = self.request()
        changed = [
            {**original, "arguments": [*original["arguments"], "-Copt-level=3"]},
            {**original, "directory": "/other/source"},
            {**original, "environment": {"CARGO_PKG_VERSION": "2.0.0"}},
        ]
        for request in changed:
            with self.subTest(request=request):
                self.assertNotEqual(compilation_inventory([original]), compilation_inventory([request]))


if __name__ == "__main__":
    unittest.main()

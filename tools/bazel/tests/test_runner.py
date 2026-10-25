"""Exercises isolated test scheduling, failures, cancellation, and policy drift."""

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load_module("aos_test_runner", ROOT / "testing/runner.py")
converter = load_module("aos_test_policy", ROOT / "metadata/test_policy.py")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.binary = self.root / "libtest"
        self.configuration = self.root / "libtest.json"
        self.log = self.root / "events.jsonl"
        self.policy = {"schema_version": 1, "default_timeout_seconds": 5, "overrides": []}
        self.binary.write_text(f"#!{sys.executable}\n" + r'''
import json, os, signal, sys, time
from pathlib import Path

configuration = json.loads(Path(__file__).with_suffix('.json').read_text())
cases = configuration['cases']
if '--list' in sys.argv:
    for name, case in sorted(cases.items()):
        if '--ignored' not in sys.argv or case.get('ignored', False):
            print(f'{name}: test')
    raise SystemExit(0)

name = sys.argv[1]
case = cases[name]
if case.get('ignore_term'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
assert '--exact' in sys.argv and '--test-threads=1' in sys.argv
assert ('--ignored' in sys.argv) == case.get('ignored', False)
def record(event):
    item = json.dumps({'event': event, 'name': name, 'pid': os.getpid(), 'time': time.monotonic()}) + '\n'
    descriptor = os.open(configuration['log'], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.write(descriptor, item.encode())
    os.close(descriptor)

record('start')
if case.get('crash'):
    os.kill(os.getpid(), signal.SIGKILL)
time.sleep(case.get('sleep', 0.02))
if case.get('output'):
    print(case['output'])
record('end')
raise SystemExit(case.get('status', 0))
''')
        self.binary.chmod(0o755)

    def configure(self, cases):
        self.configuration.write_text(json.dumps({"cases": cases, "log": str(self.log)}))

    def select(self, **kwargs):
        return runner.select_cases(self.binary, "fixture", self.policy, **kwargs)

    def test_exact_filters_ignored_tests_and_zero_matches(self):
        self.configure({"suite::first": {}, "suite::first_extended": {}, "suite::ignored": {"ignored": True}})
        self.assertEqual(len(self.select(filters=["suite::first"])), 2)
        self.assertEqual([case.name for case in self.select(filters=["suite::first"], exact=True)], ["suite::first"])
        self.assertEqual(len(self.select(ignored="include")), 3)
        ignored = self.select(ignored="only")
        self.assertEqual([case.name for case in ignored], ["suite::ignored"])
        self.assertEqual(runner.execute(self.binary, ignored, 1)[0].status, "passed")
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select(filters=["missing"])

    def test_declared_empty_artifact_does_not_allow_empty_filtered_selections(self):
        self.configure({})
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select()
        self.assertEqual(self.select(allow_empty=True), [])
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select(allow_empty=True, filters=["missing"])
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select(allow_empty=True, ignored="only")

        self.configure({"ignored": {"ignored": True}})
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select(allow_empty=True)

    def test_owner_count_and_canonical_name_authenticate_selected_cases(self):
        self.configure({"owner::canonical": {}, "owner::second": {}, "other": {}})

        selected = self.select(filters=["owner::"], expected_count=2, required_cases=["owner::canonical"])

        self.assertEqual([case.name for case in selected], ["owner::canonical", "owner::second"])
        with self.assertRaisesRegex(ValueError, "selected 2 tests; expected 3"):
            self.select(filters=["owner::"], expected_count=3)
        with self.assertRaisesRegex(ValueError, "canonical tests were not selected: other"):
            self.select(filters=["owner::"], expected_count=2, required_cases=["other"])
        with self.assertRaisesRegex(ValueError, "canonical tests were not selected: owner::renamed"):
            self.select(filters=["owner::"], expected_count=2, required_cases=["owner::renamed"])

    def test_owner_guards_apply_before_sharding(self):
        self.configure({"a": {}, "b": {}, "c": {}})

        shards = [
            self.select(shard=(index, 2), expected_count=3, required_cases=["b"])
            for index in range(2)
        ]

        self.assertEqual(sorted(case.name for shard in shards for case in shard), ["a", "b", "c"])
        with self.assertRaisesRegex(ValueError, "selected 3 tests; expected 2"):
            self.select(shard=(0, 2), expected_count=2)

    def test_ignored_and_empty_allowances_cannot_bypass_owner_guards(self):
        self.configure({"active": {}, "canonical": {"ignored": True}})

        with self.assertRaisesRegex(ValueError, "selected 1 tests; expected 2"):
            self.select(expected_count=2)
        with self.assertRaisesRegex(ValueError, "canonical tests were not selected"):
            self.select(expected_count=1, required_cases=["canonical"])
        self.assertEqual(len(self.select(ignored="include", expected_count=2, required_cases=["canonical"])), 2)

        self.configure({})
        with self.assertRaisesRegex(ValueError, "selected 0 tests; expected 1"):
            self.select(allow_empty=True, expected_count=1)
        for count in [0, -1, True]:
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "positive integer"):
                self.select(allow_empty=True, expected_count=count)
        for names in [[""], ["canonical", "canonical"]]:
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "nonempty and unique"):
                self.select(required_cases=names)

    def test_cli_rejects_invalid_owner_inventory_before_starting_any_case(self):
        self.configure({"canonical": {}, "second": {}})
        policy = self.root / "policy.json"
        policy.write_text(json.dumps(self.policy))

        for arguments, message in [
            (["--expected-count=3", "--require-case=canonical"], "selected 2 tests; expected 3"),
            (["--expected-count=2", "--require-case=renamed"], "canonical tests were not selected: renamed"),
        ]:
            with self.subTest(arguments=arguments):
                result = subprocess.run([
                    sys.executable, str(ROOT / "testing/runner.py"), "--binary", str(self.binary),
                    "--package", "fixture", "--policy", str(policy), *arguments,
                ], capture_output=True, text=True, timeout=5)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.log.exists(), "an owner test started before inventory validation")

    def test_declared_ignored_suite_preserves_inventory_and_filter_failures(self):
        self.configure({"live_service": {"ignored": True}})

        self.assertEqual(self.select(allow_ignored_only=True), [])
        selected = self.select(allow_ignored_only=True, ignored="only")
        self.assertEqual([case.name for case in selected], ["live_service"])
        self.assertEqual(runner.execute(self.binary, selected, 1)[0].status, "passed")

        for filters in [["missing"], ["live_service"]]:
            with self.assertRaisesRegex(ValueError, "zero cases"):
                self.select(allow_ignored_only=True, filters=filters)

        self.configure({})
        with self.assertRaisesRegex(ValueError, "zero cases"):
            self.select(allow_ignored_only=True)

    def test_declared_ignored_suite_still_executes_new_active_cases(self):
        self.configure({"live_service": {"ignored": True}, "active": {}})

        selected = self.select(allow_ignored_only=True)

        self.assertEqual([case.name for case in selected], ["active"])
        self.assertEqual(runner.execute(self.binary, selected, 1)[0].status, "passed")

    def test_distinct_processes_bounded_concurrency_and_exclusive_case(self):
        self.configure({name: {"sleep": 0.08} for name in ["a", "b", "exclusive", "z", "zz"]})
        self.policy["overrides"] = [{"conditions": [{"substring": "exclusive"}], "exclusive": True}]
        results = runner.execute(self.binary, self.select(), jobs=2)
        self.assertTrue(all(result.status == "passed" for result in results))
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        active = set()
        process_ids = set()
        maximum = 0
        for event in events:
            name = event["name"]
            if event["event"] == "start":
                if name == "exclusive":
                    self.assertFalse(active)
                self.assertNotIn("exclusive", active)
                active.add(name)
                maximum = max(maximum, len(active))
                process_ids.add(event["pid"])
                self.assertLessEqual(len(active), 2)
            else:
                active.remove(name)
        self.assertFalse(active)
        self.assertEqual(len(process_ids), 5)
        self.assertEqual(maximum, 2)

    def test_failures_crashes_and_timeouts_remain_failures(self):
        self.configure({"passed": {}, "failed": {"status": 7, "output": "x" * 70000},
                        "crashed": {"crash": True}, "timed_out": {"sleep": 5},
                        "stubborn": {"sleep": 5, "ignore_term": True}})
        self.policy["overrides"] = [{"conditions": [{"regex": "timed_out|stubborn"}],
                                     "timeout_seconds": 0.15, "termination_grace_seconds": 0.1}]
        results = {result.case.name: result for result in runner.execute(self.binary, self.select(), jobs=4)}
        self.assertEqual({name: result.status for name, result in results.items()}, {
            "passed": "passed", "failed": "failed", "crashed": "crashed", "timed_out": "timed-out", "stubborn": "timed-out",
        })
        self.assertTrue(results["failed"].output.startswith("[earlier output truncated]"))
        self.assertLess(results["timed_out"].elapsed, 3)
        self.assertEqual(results["stubborn"].returncode, -signal.SIGKILL)
        junit = self.root / "junit.xml"
        runner.write_junit(junit, "fixture", list(results.values()))
        self.assertEqual(len(runner.ET.parse(junit).findall("testcase/failure")), 4)

    def test_junit_preserves_passing_fixture_skip_output_and_failure_details(self):
        self.configure({
            "conditional_fixture": {"output": "fixture unavailable; skipping", "status": 0},
            "failure": {"output": "assertion failed", "status": 1},
        })

        results = runner.execute(self.binary, self.select(), jobs=2)
        output = self.root / "results.xml"
        runner.write_junit(output, "fixture", results)

        suite = ET.parse(output).getroot()
        cases = {case.attrib["name"]: case for case in suite.findall("testcase")}
        self.assertEqual(suite.attrib["failures"], "1")
        self.assertIsNone(cases["conditional_fixture"].find("failure"))
        self.assertIn("fixture unavailable; skipping", cases["conditional_fixture"].findtext("system-out"))
        self.assertIn("assertion failed", cases["failure"].findtext("failure"))

    def test_sigterm_cancels_active_cases(self):
        self.configure({"slow": {"sleep": 10}})
        policy = self.root / "policy.json"
        policy.write_text(json.dumps(self.policy))
        process = subprocess.Popen([
            sys.executable, str(ROOT / "testing/runner.py"), "--binary", str(self.binary),
            "--package", "fixture", "--policy", str(policy),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 5
            while not self.log.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.log.exists(), "test case did not start")
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 1, output)
            self.assertIn("CANCELLED: slow", output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_policy_precedence_and_stable_sharding(self):
        self.configure({"a": {}, "b": {}, "c": {}})
        self.policy["overrides"] = [
            {"conditions": [{"substring": "a"}], "timeout_seconds": 3},
            {"conditions": [{"substring": "a"}], "timeout_seconds": 9, "exclusive": True},
        ]
        selected = self.select()
        self.assertEqual(selected[0].timeout, 3)
        self.assertTrue(selected[0].exclusive)
        shards = [self.select(shard=(index, 2)) for index in range(2)]
        self.assertEqual(sorted(case.name for shard in shards for case in shard), ["a", "b", "c"])

    def test_policy_update_rejects_unknown_filter_semantics(self):
        self.assertEqual(converter.conditions("package(crucible-campaign) & test(/ten_thousand_/)"), [
            {"package_substring": "crucible-campaign"}, {"regex": "ten_thousand_"},
        ])
        for expression in ["test(a) | test(b)", "binary(unknown)", "test(=exact)"]:
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                converter.conditions(expression)


if __name__ == "__main__":
    unittest.main()

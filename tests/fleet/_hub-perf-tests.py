"""Pure regressions for paired timings and exact process identity selection."""

import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


perf = load("fleet_perf", "_hub-perf.py")
proc = load("fleet_perf_proc", "_hub-perf-proc.py")
ROW = "0.100000 200 0.020000 0.080000 0.010000 0.085000 0.120000 1"


class PairedTimingTests(unittest.TestCase):
    def test_phases_come_from_each_request_and_preserve_raw_values(self):
        samples = perf.parse_page_observations(ROW + "|||", 1)
        sample = samples[0]
        self.assertEqual(sample["curl_cumulative_raw"]["time_starttransfer"], "0.100000")
        self.assertAlmostEqual(sample["phase_seconds"]["tls_after_tcp"], 0.06)
        self.assertAlmostEqual(sum(sample["phase_seconds"].values()), 0.12)
        self.assertEqual(sample["span_association"], "unavailable")
        self.assertIsNone(sample["response_request_id"])

    def test_response_spans_stay_paired_without_retaining_descriptions(self):
        private = "private-token-cookie-value"
        row = ROW + f'|huborigin;dur=2;desc="{private}", hubworker;dur=3|fleet-page-1|'
        sample = perf.parse_page_observations(row, 1)[0]
        self.assertEqual(sample["response_spans_ms"]["huborigin"]["milliseconds"], 2)
        self.assertEqual(sample["response_request_id"], "fleet-page-1")
        self.assertEqual(sample["span_association"], "same_response")
        self.assertNotIn(private, str(sample))

    def test_quoted_descriptions_do_not_invent_numeric_spans(self):
        spans = perf.parse_response_spans(
            'huborigin;dur=2;desc="SQL, invented;dur=99", hubworker;dur=3'
        )
        self.assertEqual(set(spans), {"huborigin", "hubworker"})
        self.assertEqual(perf.parse_response_spans("hubworker;dur=1e5"), {})

    def test_nonfinite_regressed_failed_or_reused_connections_reject(self):
        for bad in [ROW.replace("0.100000", "nan"), ROW.replace("0.080000", "inf"),
                    ROW.replace("0.085000", "0.070000"), ROW.replace("200", "401"),
                    ROW[:-1] + "0", ROW.replace("0.010000", "-0.010000")]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                perf.parse_page_observations(bad + "|||", 1)
        with self.assertRaises(ValueError):
            perf.parse_page_observations(ROW + "|||", 2)

    def test_duplicate_spans_conflicting_ids_and_oversize_reject(self):
        for row in [ROW + "|huborigin;dur=1, huborigin;dur=2||",
                    ROW + "||fleet-one|fleet-two", ROW + "|" + "x" * 4097 + "||"]:
            with self.assertRaises(ValueError):
                perf.parse_page_observations(row, 1)
        sample = perf.parse_page_observations(ROW + "||Bearer-private-secret|", 1)[0]
        self.assertIsNone(sample["response_request_id"])
        self.assertNotIn("private-secret", str(sample))

    def test_counter_deltas_never_adopt_restarted_identity(self):
        before = {"processes": {role: {
            "pid": index, "start_ticks": 10, "exe": "/qualified/runtime",
            "cpu_ticks": {"user": 1}, "schedstat": {"runtime_ns": 20}, "io": {"rchar": 30},
        } for index, role in enumerate(("node", "workerd"), 1)}}
        after = copy.deepcopy(before)
        after["processes"]["workerd"]["start_ticks"] += 1
        with contextlib.redirect_stdout(io.StringIO()):
            result = perf.report_process_window("fixture", before, after)
        self.assertEqual(result["process_deltas"]["workerd"]["status"], "process_identity_changed")
        after = copy.deepcopy(before)
        after["processes"]["node"]["io"]["rchar"] = 29
        with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            perf.report_process_window("fixture", before, after)


class ProcessIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / "proc"
        self.node = self.root / "node"
        self.workerd = self.root / "workerd"
        self.node.touch()
        self.workerd.touch()
        self.make_process(10, 1, self.node)
        self.make_process(20, 10, self.workerd)
        children = self.proc / "10/task/10/children"
        children.parent.mkdir(parents=True)
        children.write_text("20")

    def make_process(self, pid, parent, exe):
        directory = self.proc / str(pid)
        directory.mkdir(parents=True)
        (directory / "exe").symlink_to(exe)
        fields = ["0"] * 50
        fields[0], fields[1], fields[11], fields[12], fields[19] = "S", str(parent), "2", "3", "123"
        (directory / "stat").write_text(f"{pid} (safe ) comm) " + " ".join(fields))
        (directory / "schedstat").write_text("400 500 6")
        (directory / "io").write_text("\n".join(f"{name}: 7" for name in (
            "rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes", "cancelled_write_bytes",
        )))

    def test_exact_executables_parent_starttime_and_units_are_retained(self):
        result = proc.snapshot(self.proc, 10, self.node, self.workerd)
        self.assertEqual(result["processes"]["workerd"]["ppid"], 10)
        self.assertEqual(result["processes"]["workerd"]["start_ticks"], 123)
        self.assertEqual(result["processes"]["node"]["cpu_ticks"], {"user": 2, "system": 3})
        self.assertEqual(result["processes"]["workerd"]["schedstat"]["runqueue_ns"], 500)
        self.assertNotIn("argv", str(result))

    def test_missing_children_interface_uses_exact_bounded_parent_discovery(self):
        (self.proc / "10/task/10/children").unlink()
        self.make_process(30, 1, self.workerd)
        result = proc.snapshot(self.proc, 10, self.node, self.workerd)
        self.assertEqual(result["child_discovery"], "bounded_proc_parent_scan")
        self.assertEqual(result["processes"]["workerd"]["pid"], 20)
        self.make_process(40, 10, self.workerd)
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)

    def test_fallback_never_adopts_wrong_parent_or_wrong_executable(self):
        (self.proc / "10/task/10/children").unlink()
        stat = self.proc / "20/stat"
        original = stat.read_text()
        stat.write_text(original.replace(") S 10 ", ") S 11 "))
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)
        stat.write_text(original)
        (self.proc / "20/exe").unlink()
        (self.proc / "20/exe").symlink_to(self.node)
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)

    def test_fallback_scan_is_bounded_and_present_invalid_children_do_not_fallback(self):
        children = self.proc / "10/task/10/children"
        children.write_text("invalid")
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)
        children.unlink()
        class Entry:
            name = "1"
        with patch.object(Path, "iterdir", return_value=iter([Entry()] * 4097)):
            with self.assertRaisesRegex(ValueError, "discovery exceeds bounds"):
                proc.runtime_children(self.proc, 10)

    def test_absent_optional_counters_keep_mandatory_identity_and_cpu(self):
        (self.proc / "10/schedstat").unlink()
        (self.proc / "20/io").unlink()
        before = proc.snapshot(self.proc, 10, self.node, self.workerd)
        self.assertIsNone(before["processes"]["node"]["schedstat"])
        self.assertIsNone(before["processes"]["workerd"]["io"])
        self.assertEqual(before["processes"]["node"]["optional_counter_status"]["schedstat"],
                         {"status": "unavailable", "reason": "not_supported"})
        self.assertEqual(before["processes"]["workerd"]["start_ticks"], 123)
        self.assertEqual(before["processes"]["node"]["cpu_ticks"]["user"], 2)
        with contextlib.redirect_stdout(io.StringIO()):
            result = perf.report_process_window("fixture", before, copy.deepcopy(before))
        self.assertIsNone(result["process_deltas"]["node"]["schedstat"])
        self.assertIsNone(result["process_deltas"]["workerd"]["io"])
        self.assertEqual(result["process_deltas"]["node"]["cpu_ticks"]["user"], 0)

    def test_optional_permission_and_malformed_counters_are_explicit(self):
        for error, reason in ((PermissionError("private"), "permission_denied"),
                              (OSError("private"), "read_error"),
                              (ValueError("private"), "invalid_counters")):
            with self.subTest(reason=reason):
                def denied(_):
                    raise error
                value, status = proc.optional_counters(Path("unused"), denied)
                self.assertIsNone(value)
                self.assertEqual(status, {"status": "unavailable", "reason": reason})
                self.assertNotIn("private", str(status))
        (self.proc / "10/schedstat").write_text("-1 2 3")
        (self.proc / "20/io").write_text("rchar: private")
        result = proc.snapshot(self.proc, 10, self.node, self.workerd)
        self.assertIsNone(result["processes"]["node"]["schedstat"])
        self.assertIsNone(result["processes"]["workerd"]["io"])

    def test_parent_change_during_final_identity_read_rejects(self):
        original = proc.read_process
        calls = 0
        def changed_parent(*args):
            nonlocal calls
            record = original(*args)
            calls += 1
            if calls == 4:
                record["ppid"] = 99
            return record
        with patch.object(proc, "read_process", side_effect=changed_parent):
            with self.assertRaisesRegex(ValueError, "identity changed during collection"):
                proc.snapshot(self.proc, 10, self.node, self.workerd)

    def test_optional_availability_change_does_not_invent_delta(self):
        before = proc.snapshot(self.proc, 10, self.node, self.workerd)
        (self.proc / "20/io").unlink()
        after = proc.snapshot(self.proc, 10, self.node, self.workerd)
        with contextlib.redirect_stdout(io.StringIO()):
            result = perf.report_process_window("fixture", before, after)
        self.assertIsNone(result["process_deltas"]["workerd"]["io"])
        (self.proc / "20/stat").unlink()
        with self.assertRaises(FileNotFoundError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)

    def test_wrong_executable_multiple_children_and_wrong_parent_reject(self):
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.workerd, self.workerd)
        self.make_process(30, 10, self.workerd)
        (self.proc / "10/task/10/children").write_text("20 30")
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)
        (self.proc / "10/task/10/children").write_text("30")
        stat = self.proc / "30/stat"
        stat.write_text(stat.read_text().replace(") S 10 ", ") S 11 "))
        with self.assertRaises(ValueError):
            proc.snapshot(self.proc, 10, self.node, self.workerd)


if __name__ == "__main__":
    unittest.main()

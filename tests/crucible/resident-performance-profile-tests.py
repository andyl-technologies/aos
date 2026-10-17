"""Check scheduling diagnostic completeness and original-driver instrumentation."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("resident-performance-profile.py")
SPEC = importlib.util.spec_from_file_location("resident_profile", MODULE)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def snapshot(threads, start=100):
    return {
        "pid": 123, "process": {"start_ticks": start, "user_ticks": 10,
                                "system_ticks": 2},
        "threads": threads, "missing_during_read": [],
    }


def thread(runtime, wait, slices, start=100):
    return {"start_ticks": start, "runtime_ns": runtime,
            "runqueue_wait_ns": wait, "timeslices": slices}


class SchedulingDiagnosticsTests(unittest.TestCase):
    def test_native_kernel_identity_records_the_real_uname_fields(self):
        result = PROFILE.kernel_identity()
        self.assertEqual(result["release"], PROFILE.os.uname().release)
        self.assertEqual(set(result), {"sysname", "nodename", "release", "version", "machine"})

    def test_predeclared_plan_matches_exact_package_and_records_original_bytes(self):
        metadata = {
            "sampling_plan": {"pairs_per_workload_mode": 40},
            "cpu": 5, "stop": 240000000, "checkpoint": 120000000,
            "timeout_seconds": 120,
            "clock_ticks_per_second": 100, "scheduling_counters_available": False,
            "kernel": {"release": "fixture-kernel"},
            "started_utc": "2026-10-06T01:00:00+00:00",
            "driver": {"sha256": "driver"},
            "artifacts": {variant: {field: field for field in
                          ("source_driver", "qemu", "plugin", "roms", "identity",
                           "normalized_guest_commands")} for variant in ("baseline", "current")},
        }
        plan = dict(json.loads(json.dumps(metadata)), schema="crucible.resident.confirmation-plan.v1",
                    status="bound", measurement_driver_sha256="driver",
                    bound_utc="2026-10-06T00:00:00+00:00")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_text(json.dumps(plan))
            PROFILE.bind_predeclared_plan(metadata, path)
            self.assertEqual(metadata["predeclared_plan"], PROFILE.file_identity(path))

            plan["artifacts"]["current"]["qemu"] = "changed-package"
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, "current qemu"):
                PROFILE.bind_predeclared_plan(metadata, path)

    def test_required_disabled_counters_refuse_before_output_or_guest_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "measurement"
            arguments = [str(MODULE), "--cpu", "5", "--output", str(output),
                         "--require-scheduling-counters"]
            for label in ("baseline", "current"):
                for kind in ("source", "qemu", "fixtures"):
                    arguments.extend([f"--{label}-{kind}", "/unused"])
            with (patch("sys.argv", arguments),
                  patch.object(PROFILE.os, "sched_getaffinity", return_value={5}),
                  patch.object(PROFILE.os, "sched_setaffinity") as affinity,
                  patch.object(Path, "read_text", return_value="0"),
                  patch.object(PROFILE, "observed_boundary") as boundary,
                  contextlib.redirect_stderr(io.StringIO()),
                  self.assertRaises(SystemExit) as refusal):
                PROFILE.main()
            self.assertEqual(refusal.exception.code, 2)
            self.assertFalse(output.exists())
            affinity.assert_not_called()
            boundary.assert_not_called()

    def test_disabled_counters_retain_cpu_ticks_without_interpreting_schedstat(self):
        before = snapshot({"1": thread(100, 0, 1)})
        after = snapshot({"1": thread(200, 0, 2)})
        after["process"]["user_ticks"] = 13
        result = PROFILE.scheduling_delta(before, after, counters_available=False)

        self.assertFalse(result["scheduling_counters_available"])
        self.assertIsNone(result["stable_thread_deltas"])
        self.assertIsNone(result["stable_thread_totals"])
        self.assertEqual(result["process_tick_delta"], {"user_ticks": 3, "system_ticks": 0})
        self.assertEqual(before["threads"]["1"]["runtime_ns"], 100)
        self.assertEqual(after["threads"]["1"]["runtime_ns"], 200)

    def test_stable_counters_preserve_runtime_and_wait_separately(self):
        before = snapshot({"1": thread(100, 20, 3), "2": thread(30, 4, 1)})
        after = snapshot({"1": thread(250, 90, 8), "2": thread(35, 8, 2)})
        result = PROFILE.scheduling_delta(before, after)

        self.assertTrue(result["complete_thread_coverage"])
        self.assertEqual(result["stable_thread_totals"],
                         {"runtime_ns": 155, "runqueue_wait_ns": 74, "timeslices": 6})

    def test_changed_thread_inventory_never_counts_missing_counters_as_zero(self):
        before = snapshot({"1": thread(100, 20, 3), "2": thread(30, 4, 1),
                           "3": thread(90, 1, 1), "4": thread(80, 1, 1)})
        after = snapshot({"1": thread(150, 40, 4), "3": thread(10, 1, 1, 200),
                          "4": thread(70, 1, 1), "5": thread(5, 2, 1)})
        result = PROFILE.scheduling_delta(before, after)

        self.assertFalse(result["complete_thread_coverage"])
        self.assertEqual(result["born_threads"], ["5"])
        self.assertEqual(result["departed_threads"], ["2"])
        self.assertEqual(result["reused_threads"], ["3"])
        self.assertEqual(result["regressed_threads"], ["4"])
        self.assertEqual(list(result["stable_thread_deltas"]), ["1"])

    def test_process_reuse_refuses_comparison(self):
        with self.assertRaisesRegex(ValueError, "process identity"):
            PROFILE.scheduling_delta(snapshot({}), snapshot({}, start=200))

    def test_original_two_observation_sites_are_restored_after_success_and_failure(self):
        namespace = {"cpu_seconds": lambda pid: (1, 2)}
        exec("def boundary(fail=False):\n"
             "    cpu_seconds(123)\n"
             "    if fail:\n"
             "        raise RuntimeError('original failure')\n"
             "    cpu_seconds(123)\n"
             "    return {'seconds': 1}\n", namespace)
        original = namespace["cpu_seconds"]
        before, after = snapshot({"1": thread(10, 2, 1)}), snapshot({"1": thread(20, 3, 2)})

        with patch.object(PROFILE, "scheduler_snapshot", side_effect=[before, after]):
            result = PROFILE.observed_boundary({"run_boundary": namespace["boundary"]})
        self.assertTrue(result["scheduling"]["delta"]["complete_thread_coverage"])
        self.assertIs(namespace["cpu_seconds"], original)

        with patch.object(PROFILE, "scheduler_snapshot", return_value=before):
            with self.assertRaisesRegex(RuntimeError, "original failure") as failure:
                PROFILE.observed_boundary({"run_boundary": namespace["boundary"]}, fail=True)
        self.assertEqual(failure.exception.scheduling_observations, [before])
        self.assertIs(namespace["cpu_seconds"], original)


if __name__ == "__main__":
    unittest.main()

"""Check matched receipt refusal and fixed no-increase interpretation.

Synthetic timing rows exercise the evaluator only; they provide no native
performance or deployment evidence. Run with AOS-built Python.
"""

import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "resident_summary", Path(__file__).with_name("resident-performance-summary.py"))
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def fixture(factor=0.9):
    sampling = {
        "pairs_per_workload_mode": 40,
        "workloads": list(SUMMARY.WORKLOADS),
        "modes": ["cold", "restored"],
        "order": "baseline/current on even trials, current/baseline on odd trials",
        "retention": "all samples and checkpoint producers; no optional stopping or exclusions",
    }
    artifacts = {}
    for variant in SUMMARY.VARIANTS:
        artifacts[variant] = {
            "source_driver": {"path": f"/{variant}/driver", "sha256": "driver"},
            "snapshot": {"path": f"/{variant}/snapshot", "sha256": "driver"},
            "qemu": {"path": f"/{variant}/qemu", "sha256": variant},
            "plugin": {"path": f"/{variant}/plugin", "sha256": variant},
            "roms": {name: {"path": f"/{variant}/{name}", "sha256": name}
                     for name in SUMMARY.WORKLOADS},
            "identity": variant,
            "normalized_guest_commands": {"cold": ["same"], "restored": ["same"]},
        }
    plan = {
        "schema": SUMMARY.SCHEMA, "status": "bound", "pairs_per_workload_mode": 40,
        "bound_utc": "2026-10-06T00:00:00+00:00",
        "cpu": 5, "stop": 240_000_000, "checkpoint": 120_000_000,
        "timeout_seconds": 120,
        "clock_ticks_per_second": 100, "scheduling_counters_available": False,
        "kernel": {"release": "fixture-kernel"},
        "measurement_driver_sha256": "instrumentation", "sampling_plan": sampling,
        "artifacts": copy.deepcopy(artifacts), "verdict_criteria": SUMMARY.VERDICT_CRITERIA,
        "witness_scope": "Synthetic evaluator test; no native qualification",
    }
    manifest = {field: plan[field] for field in
                ("cpu", "stop", "checkpoint", "timeout_seconds", "clock_ticks_per_second",
                 "scheduling_counters_available", "sampling_plan")}
    manifest["kernel"] = plan["kernel"]
    manifest.update({"started_utc": "2026-10-06T01:00:00+00:00",
                     "completed_utc": "2026-10-06T02:00:00+00:00",
                     "predeclared_plan": {"sha256": "plan"},
                     "driver": {"sha256": "instrumentation"}, "artifacts": artifacts})
    rows = []
    for workload in SUMMARY.WORKLOADS:
        for trial in range(40):
            variants = SUMMARY.VARIANTS if trial % 2 == 0 else tuple(reversed(SUMMARY.VARIANTS))
            for variant in variants:
                ratio = factor if variant == "current" else 1
                user, system = round(200 * ratio), round(50 * ratio)
                for mode in SUMMARY.MODES:
                    stop = plan["checkpoint"] if mode == "source" else plan["stop"]
                    rows.append({
                        "workload": workload, "mode": mode, "variant": variant, "trial": trial,
                        "seconds": 10 * ratio, "user_seconds": user / 100,
                        "system_seconds": system / 100,
                        "witness": {"raw_icount": stop, "logical_tick": stop * 50,
                                    "registers": workload, "ram_sha256": workload,
                                    "ram_prefix_hex": workload},
                        "scheduling": {
                            "before": {"pid": 123, "process": {"start_ticks": 20,
                                       "user_ticks": 100, "system_ticks": 10}},
                            "after": {"pid": 123, "process": {"start_ticks": 20,
                                      "user_ticks": 100 + user, "system_ticks": 10 + system}},
                            "delta": {"scheduling_counters_available": False,
                                      "process_tick_delta": {"user_ticks": user, "system_ticks": system},
                                      "stable_thread_deltas": None, "stable_thread_totals": None},
                        },
                    })

    def require_reference(row, stop, loop):
        if row["witness"]["raw_icount"] != stop or row["witness"]["logical_tick"] != stop * 50:
            raise ValueError("independent boundary oracle differs")

    drivers = {variant: {"require_reference": require_reference} for variant in SUMMARY.VARIANTS}
    return plan, manifest, rows, drivers


class PerformanceSummaryTests(unittest.TestCase):
    def evaluate(self, data):
        return SUMMARY.evaluate(*data, "plan")

    def test_complete_lower_cost_receipt_keeps_every_pair_and_producer(self):
        result = self.evaluate(fixture())
        self.assertEqual(result["verdict"], "no_regression_supported_for_measured_profile")
        self.assertEqual(result["sample_count"], 480)
        self.assertEqual(result["primary_observations"], 320)
        self.assertEqual(result["checkpoint_producer_observations"], 160)
        self.assertEqual(len(result["groups"]), 6)
        self.assertFalse(result["scheduling_counters_available"])
        for group in result["groups"].values():
            for metric in group.values():
                self.assertEqual(len(metric["paired_ratios_current_over_baseline"]), 40)

    def test_positive_cost_interval_reports_regression_without_a_margin(self):
        result = self.evaluate(fixture(1.1))
        self.assertEqual(result["verdict"], "regression_detected")
        metric = result["groups"]["io-bios.bin/restored"]["process_cpu_seconds"]
        self.assertGreater(metric["normal_approximation_95_percent_ratio_interval"][0], 1)

    def test_large_observation_is_retained_and_cannot_be_removed_for_acceptance(self):
        data = fixture(1)
        row = next(row for row in data[2] if row["variant"] == "current")
        row["seconds"] = 100
        result = self.evaluate(data)
        metric = result["groups"]["bios.bin/cold"]["wall_seconds"]
        self.assertEqual(metric["current"]["maximum"], 100)
        self.assertEqual(len(metric["current"]["values"]), 40)
        self.assertFalse(metric["current_maximum_does_not_increase"])
        self.assertEqual(result["verdict"], "no_regression_not_demonstrated")

    def test_missing_duplicate_and_reordered_pairs_refuse(self):
        for mutation in (lambda rows: rows.pop(),
                         lambda rows: rows.__setitem__(-1, copy.deepcopy(rows[0])),
                         lambda rows: rows.reverse()):
            with self.subTest(mutation=mutation):
                data = fixture()
                mutation(data[2])
                with self.assertRaises(ValueError):
                    self.evaluate(data)

    def test_changed_artifact_profile_plan_and_criteria_refuse(self):
        for change in (lambda plan, manifest: manifest.update(cpu=6),
                       lambda plan, manifest: manifest["artifacts"]["current"]["qemu"].update(sha256="changed"),
                       lambda plan, manifest: manifest["predeclared_plan"].update(sha256="other"),
                       lambda plan, manifest: plan.update(bound_utc="2026-10-06T03:00:00+00:00"),
                       lambda plan, manifest: plan.update(status="waiting_for_final_package"),
                       lambda plan, manifest: plan.update(verdict_criteria={"margin": 0.1})):
            with self.subTest(change=change):
                data = fixture()
                change(data[0], data[1])
                with self.assertRaises(ValueError):
                    self.evaluate(data)

    def test_witness_cpu_identity_and_disabled_counter_corruption_refuse(self):
        for change in (lambda row: row["witness"].update(ram_sha256="corrupt"),
                       lambda row: row.update(user_seconds=999),
                       lambda row: row["scheduling"]["after"]["process"].update(start_ticks=21),
                       lambda row: row["scheduling"]["delta"].update(stable_thread_totals={"runtime_ns": 0})):
            with self.subTest(change=change):
                data = fixture()
                change(data[2][-1])
                with self.assertRaises(ValueError):
                    self.evaluate(data)


if __name__ == "__main__":
    unittest.main()

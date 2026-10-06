"""Validate one predeclared paired resident receipt and interpret its timings.

This evaluates the measured component profile only. It retains every matched
pair and reports wall and process CPU uncertainty separately from raw median
and maximum checks. It does not qualify a managed deployment or whole-RAM
canonical identity. Run with AOS-built Python.
"""

import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import runpy
import statistics


SCHEMA = "crucible.resident.confirmation-plan.v1"
VARIANTS = ("baseline", "current")
WORKLOADS = {"bios.bin": 7, "io-bios.bin": 8}
MODES = ("cold", "source", "restored")
VERDICT_CRITERIA = {
    "primary_groups": "BIOS and POST, cold and restored; checkpoint producers are diagnostic only",
    "metrics": "wall seconds and process user plus system CPU seconds",
    "margin": 0,
    "increase": "any primary paired log-ratio normal 95% interval has lower endpoint greater than 1",
    "support": "every primary interval upper endpoint is at most 1 and every current raw median and maximum is at most its baseline counterpart",
    "otherwise": "no_regression_not_demonstrated",
}


def require(condition, reason):
    """Refuse mismatched or incomplete evidence before interpreting timings."""
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution(values):
    """Retain raw observations and descriptive endpoints without trimming."""
    return {
        "values": values,
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }


def paired_metric(pairs):
    """Report the same approximate log-ratio interval as preceding datasets."""
    baseline = [pair["baseline"] for pair in pairs]
    current = [pair["current"] for pair in pairs]
    require(all(math.isfinite(value) and value > 0
                for value in baseline + current), "nonpositive or nonfinite measured interval")
    ratios = [new / old for old, new in zip(baseline, current)]
    logs = [math.log(ratio) for ratio in ratios]
    mean = statistics.mean(logs)
    error = 1.96 * statistics.stdev(logs) / math.sqrt(len(logs))
    interval = [math.exp(mean - error), math.exp(mean + error)]
    return {
        "baseline": distribution(baseline),
        "current": distribution(current),
        "paired_ratios_current_over_baseline": ratios,
        "geometric_mean_ratio": math.exp(mean),
        "normal_approximation_95_percent_ratio_interval": interval,
        "interval_classification": (
            "increase_supported" if interval[0] > 1 else
            "no_increase_supported" if interval[1] <= 1 else
            "unresolved"
        ),
        "current_median_does_not_increase": statistics.median(current) <= statistics.median(baseline),
        "current_maximum_does_not_increase": max(current) <= max(baseline),
    }


def validate_inputs(plan, manifest, plan_hash):
    require(plan["schema"] == SCHEMA, "unknown predeclared plan schema")
    require(plan["status"] == "bound", "final package has not been bound before measurement")
    require(plan["pairs_per_workload_mode"] == 40, "confirmation requires exactly forty pairs")
    require(plan["verdict_criteria"] == VERDICT_CRITERIA, "verdict criteria differ from the declared evaluator")
    require(manifest.get("completed_utc") and "failure" not in manifest,
            "measurement did not complete successfully")
    bound = datetime.datetime.fromisoformat(plan["bound_utc"])
    started = datetime.datetime.fromisoformat(manifest["started_utc"])
    completed = datetime.datetime.fromisoformat(manifest["completed_utc"])
    require(all(value.tzinfo is not None for value in (bound, started, completed)) and
            bound <= started <= completed, "plan was not bound before the complete measurement")
    require(manifest["predeclared_plan"]["sha256"] == plan_hash,
            "receipt names a different predeclared plan")
    require(manifest["driver"]["sha256"] == plan["measurement_driver_sha256"],
            "measurement instrumentation differs from the plan")
    require(manifest["sampling_plan"] == plan["sampling_plan"], "sampling plan differs")
    for field in ("cpu", "stop", "checkpoint", "timeout_seconds", "clock_ticks_per_second"):
        require(manifest[field] == plan[field], f"measured {field} differs from plan")
    require(manifest["kernel"] == plan["kernel"], "measured host kernel differs from plan")
    require(manifest["scheduling_counters_available"] == plan["scheduling_counters_available"],
            "scheduling counter availability differs from plan")
    for variant in VARIANTS:
        actual, expected = manifest["artifacts"][variant], plan["artifacts"][variant]
        for field in ("source_driver", "qemu", "plugin", "roms", "identity",
                      "normalized_guest_commands"):
            require(actual[field] == expected[field], f"{variant} {field} differs from plan")
        require(actual["snapshot"]["sha256"] == expected["source_driver"]["sha256"],
                f"{variant} original boundary driver snapshot differs")
    require(all(plan["artifacts"]["baseline"]["roms"][name]["sha256"] ==
                plan["artifacts"]["current"]["roms"][name]["sha256"] for name in WORKLOADS),
            "paired ROM identities differ")
    require(plan["artifacts"]["baseline"]["normalized_guest_commands"] ==
            plan["artifacts"]["current"]["normalized_guest_commands"],
            "paired guest configurations differ")


def validate_samples(plan, manifest, rows, drivers):
    """Authenticate all planned rows, CPU reads and existing execution witnesses."""
    pairs = plan["pairs_per_workload_mode"]
    require(len(rows) == pairs * len(WORKLOADS) * len(MODES) * len(VARIANTS),
            "missing or additional rows in the predeclared dataset")
    indexed, witnesses = {}, {}
    for row in rows:
        workload, mode, variant, trial = (row[field] for field in
                                          ("workload", "mode", "variant", "trial"))
        require(workload in WORKLOADS and mode in MODES and variant in VARIANTS,
                "unknown workload, mode or variant")
        require(type(trial) is int and 0 <= trial < pairs, "trial outside planned range")
        key = (workload, mode, trial, variant)
        require(key not in indexed, "duplicate measured pair member")
        indexed[key] = row
        stop = plan["checkpoint"] if mode == "source" else plan["stop"]
        drivers[variant]["require_reference"](row, stop, WORKLOADS[workload])
        witness_key = (workload, mode == "source")
        expected = witnesses.setdefault(witness_key, row["witness"])
        require(row["witness"] == expected, "existing execution witness differs across pairs")

        scheduling = row["scheduling"]
        before, after, delta = (scheduling[field] for field in ("before", "after", "delta"))
        require(before["pid"] == after["pid"] and
                before["process"]["start_ticks"] == after["process"]["start_ticks"],
                "process identity changed during a measurement")
        ticks = manifest["clock_ticks_per_second"]
        for field, seconds in (("user_ticks", "user_seconds"), ("system_ticks", "system_seconds")):
            value = after["process"][field] - before["process"][field]
            require(value >= 0 and delta["process_tick_delta"][field] == value,
                    "process CPU accounting regressed or differs from raw reads")
            require(math.isclose(row[seconds], value / ticks, rel_tol=0, abs_tol=1e-9),
                    "reported CPU time differs from retained process ticks")
        available = manifest["scheduling_counters_available"]
        require(delta["scheduling_counters_available"] == available,
                "row scheduling availability differs from manifest")
        if not available:
            require(delta["stable_thread_deltas"] is None and delta["stable_thread_totals"] is None,
                    "disabled scheduling counters were interpreted as measurements")

    expected_order = [
        (workload, mode, trial, variant)
        for workload in WORKLOADS
        for trial in range(pairs)
        for variant in (VARIANTS if trial % 2 == 0 else tuple(reversed(VARIANTS)))
        for mode in MODES
    ]
    require(list(indexed) == expected_order, "receipt violates the predeclared interleaving order")
    return indexed


def evaluate(plan, manifest, rows, drivers, plan_hash):
    validate_inputs(plan, manifest, plan_hash)
    indexed = validate_samples(plan, manifest, rows, drivers)
    groups, primary = {}, []
    for workload in WORKLOADS:
        for mode in MODES:
            metrics = {}
            for metric, fields in (("wall_seconds", ("seconds",)),
                                   ("process_cpu_seconds", ("user_seconds", "system_seconds"))):
                pairs = [
                    {variant: sum(indexed[workload, mode, trial, variant][field]
                                  for field in fields) for variant in VARIANTS}
                    for trial in range(plan["pairs_per_workload_mode"])
                ]
                metrics[metric] = paired_metric(pairs)
                if mode != "source":
                    primary.append(metrics[metric])
            groups[f"{workload}/{mode}"] = metrics

    increase = any(metric["interval_classification"] == "increase_supported" for metric in primary)
    supported = all(metric["interval_classification"] == "no_increase_supported" and
                    metric["current_median_does_not_increase"] and
                    metric["current_maximum_does_not_increase"] for metric in primary)
    return {
        "schema": "crucible.resident.performance-summary.v1",
        "plan_sha256": plan_hash,
        "sample_count": len(rows),
        "primary_observations": 320,
        "checkpoint_producer_observations": 160,
        "verdict": ("regression_detected" if increase else
                    "no_regression_supported_for_measured_profile" if supported else
                    "no_regression_not_demonstrated"),
        "criteria": plan["verdict_criteria"],
        "groups": groups,
        "scheduling_counters_available": manifest["scheduling_counters_available"],
        "scope": plan["witness_scope"],
        "limitations": [
            "Intervals are individual normal approximations to paired log ratios, assume stable sampling, and have no multiple-comparison adjustment.",
            "CPU observations are quantized by the recorded process clock tick rate and straddle the original wall ROI.",
            "Raw median and maximum checks are separate observations; a maximum alone does not identify a CPU regression.",
            "The four primary groups cover component resident BIOS/POST cold and restored execution, not managed deployment or canonical whole-RAM identity costs.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    require(digest(Path(__file__).resolve()) == plan["summary_evaluator_sha256"],
            "summary evaluator differs from the predeclared code")
    manifest = json.loads((args.receipt / "evidence.json").read_text())
    rows = [json.loads(line) for line in (args.receipt / "samples.jsonl").read_text().splitlines()]
    drivers = {}
    for variant in VARIANTS:
        snapshot = Path(manifest["artifacts"][variant]["snapshot"]["path"])
        require(digest(snapshot) == plan["artifacts"][variant]["source_driver"]["sha256"],
                "boundary driver snapshot was changed after measurement")
        drivers[variant] = runpy.run_path(str(snapshot))
    summary = evaluate(plan, manifest, rows, drivers, digest(args.plan))
    summary["receipt_sha256"] = {
        name: digest(args.receipt / name) for name in ("evidence.json", "samples.jsonl")
    }
    with args.output.open("x") as output:
        json.dump(summary, output, indent=2)
        output.write("\n")
    print(json.dumps({"verdict": summary["verdict"], "output": str(args.output)}))


if __name__ == "__main__":
    main()

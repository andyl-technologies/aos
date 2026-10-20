# SPDX-License-Identifier: Apache-2.0
"""Retain every scheduled Linux boot trial without retrying failed launches.

Each trial delegates to an unchanged, frozen runner with one label and one
repetition. Successful readiness times are conditional on reaching readiness;
paired gains use only pairs where both scheduled trials passed. A timeout is a
censored failure, never a substituted ready time. Witness drift aborts the
campaign rather than becoming another censored trial.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import subprocess
import sys


CONFIGURATION_KEYS = ("coverage", "fingerprint", "whitebox", "ram_mib", "kernel", "initrd")


def distribution(values):
    """Summarize admitted successful times without replacing failed samples."""
    if not values:
        return None
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0,
    }


def summarize(attempts, labels):
    """Keep conditional successful distributions separate from complete pairs."""
    per_label = {}
    for label in labels:
        scheduled = [row for row in attempts if row["label"] == label]
        passed = [row for row in scheduled if row["outcome"] == "passed"]
        failed = [row for row in scheduled if row["outcome"] == "failed"]
        per_label[label] = {
            "attempts": len(scheduled),
            "passed": len(passed),
            "failed": len(failed),
            "readiness_timeout_failures": sum(row.get("censored_timeout_seconds") == 300 for row in failed),
            "successful_ready_times_are_conditional": True,
            "distributions": {
                key: distribution([row["sample"][key] for row in passed])
                for key in ("seconds", "boot_seconds", "startup_seconds", "user_seconds", "system_seconds")
            },
        }

    complete_pairs = []
    for pair in sorted({row["pair"] for row in attempts}):
        rows = {row["label"]: row for row in attempts if row["pair"] == pair}
        if all(label in rows and rows[label]["outcome"] == "passed" for label in labels):
            control = rows[labels[0]]["sample"]["seconds"]
            candidate = rows[labels[1]]["sample"]["seconds"]
            complete_pairs.append({
                "pair": pair,
                "baseline_seconds": control,
                "candidate_seconds": candidate,
                "reduction_percent": 100 * (control - candidate) / control,
                "speedup": control / candidate,
            })
    comparison = None
    if complete_pairs:
        control = statistics.mean(row["baseline_seconds"] for row in complete_pairs)
        candidate = statistics.mean(row["candidate_seconds"] for row in complete_pairs)
        comparison = {
            "baseline": labels[0],
            "candidate": labels[1],
            "complete_pair_count": len(complete_pairs),
            "baseline_mean_seconds": control,
            "candidate_mean_seconds": candidate,
            "reduction_percent": 100 * (control - candidate) / control,
            "speedup": control / candidate,
            "scope": "Only complete scheduled pairs; conditional on both trials reaching exact readiness.",
        }
    return {"per_label": per_label, "complete_pairs": complete_pairs, "complete_pair_comparison": comparison}


def write_results(path, results, labels):
    results["summary"] = summarize(results["attempts"], labels)
    path.write_text(json.dumps(results, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--qemu", action="append", required=True)
    parser.add_argument("--plugin", action="append", required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--initrd", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prior-aborted-campaign", type=Path)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--host-cpu", type=int, required=True)
    parser.add_argument("--ram-mib", type=int, default=256)
    parser.add_argument("--fingerprint", choices=("off", "on"), default="off")
    parser.add_argument("--baseline-revision", required=True)
    parser.add_argument("--candidate-revision", required=True)
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("frozen_runner", args.runner)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    qemu = runner.labeled_paths(args.qemu)
    plugins = runner.labeled_paths(args.plugin)
    labels = list(qemu)
    if len(labels) != 2 or qemu.keys() != plugins.keys() or args.repetitions < 1:
        raise ValueError("provide exactly two matched artifact labels and positive repetitions")
    if args.output.exists():
        raise ValueError("campaign output already exists; each campaign requires a new directory")

    reference = json.loads(args.reference.read_text())
    runner.require_ready_witness(reference, args.ram_mib)
    witness_keys = runner.WITNESS_KEYS + CONFIGURATION_KEYS
    args.output.mkdir(parents=True)
    destination = args.output / "results.json"
    results = {
        "policy": "Scheduled alternating pairs; every attempt retained, failed launches continue, no retries or replacements; witness drift aborts.",
        "timing_scope": "Unchanged frozen driver's launch-to-native-paused readiness interval; wrapper and runner startup are excluded.",
        "baseline_revision": args.baseline_revision,
        "candidate_revision": args.candidate_revision,
        "planned_pairs": args.repetitions,
        "labels": labels,
        "source": {"path": str(Path(__file__).resolve()), "sha256": runner.sha256(Path(__file__))},
        "runner": {"path": str(args.runner), "sha256": runner.sha256(args.runner)},
        "driver": {"path": str(args.driver), "sha256": runner.sha256(args.driver)},
        "reference": {"path": str(args.reference), "sha256": runner.sha256(args.reference), "fields": list(witness_keys)},
        "configuration": {"cpu": args.cpu, "host_cpu": args.host_cpu, "ram_mib": args.ram_mib, "fingerprint": args.fingerprint},
        "attempts": [],
        "campaign_complete": False,
    }
    if args.prior_aborted_campaign:
        prior = json.loads(args.prior_aborted_campaign.read_text())
        results["prior_aborted_campaign"] = {
            "path": str(args.prior_aborted_campaign),
            "sha256": runner.sha256(args.prior_aborted_campaign),
            "included_in_current_distributions": False,
            "attempts": [{key: row[key] for key in ("label", "repeat", "outcome", "exit_status")}
                         for row in prior["attempts"]],
        }
    write_results(destination, results, labels)

    for pair in range(args.repetitions):
        for position, label in enumerate(runner.trial_order(labels, pair)):
            directory = args.output / f"pair-{pair}-{position}-{label}"
            directory.mkdir()
            command = [
                sys.executable, str(args.runner), "--driver", str(args.driver),
                "--qemu", f"{label}={qemu[label]}", "--plugin", f"{label}={plugins[label]}",
                "--kernel", str(args.kernel), "--initrd", str(args.initrd),
                "--output", str(directory / "trial"), "--repetitions", "1",
                "--cpu", str(args.cpu), "--host-cpu", str(args.host_cpu),
                "--ram-mib", str(args.ram_mib), "--fingerprint", args.fingerprint,
                "--baseline-revision", args.baseline_revision, "--candidate-revision", args.candidate_revision,
            ]
            attempt = {"pair": pair, "position": position, "label": label,
                       "command": command, "outcome": "started"}
            results["attempts"].append(attempt)
            write_results(destination, results, labels)
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            (directory / "stdout.log").write_text(completed.stdout)
            (directory / "stderr.log").write_text(completed.stderr)
            attempt["runner_exit_status"] = completed.returncode

            trial_path = directory / "trial/results.json"
            if not trial_path.exists():
                attempt["outcome"] = "infrastructure_error"
                write_results(destination, results, labels)
                raise RuntimeError("frozen runner exited without trial provenance")
            trial = json.loads(trial_path.read_text())
            attempt["trial_results"] = str(trial_path)
            if len(trial["attempts"]) != 1:
                raise RuntimeError("single-label frozen runner did not retain exactly one attempt")
            child = trial["attempts"][0]
            if completed.returncode != 0:
                if child["outcome"] != "failed" or child.get("exit_status", 0) == 0:
                    attempt["outcome"] = "invalid_witness_or_infrastructure_error"
                    write_results(destination, results, labels)
                    raise RuntimeError("nonzero runner exit was not a captured driver launch/readiness failure")
                attempt.update(outcome="failed", driver_exit_status=child["exit_status"])
                driver_stderr = directory / "trial" / f"linux-0-{label}" / "stderr.log"
                error = driver_stderr.read_text()
                attempt["driver_stderr"] = error
                expected_failure = (
                    "Linux readiness timeout:" in error
                    or "QEMU exited before authenticated readiness" in error
                )
                if not expected_failure:
                    attempt["outcome"] = "unclassified_driver_error"
                    write_results(destination, results, labels)
                    raise RuntimeError("driver error was not a recognized launch/readiness failure")
                if "Linux readiness timeout:" in error:
                    attempt["censored_timeout_seconds"] = 300
                write_results(destination, results, labels)
                print(json.dumps({"pair": pair, "label": label, "outcome": "failed", "censored_timeout_seconds": attempt.get("censored_timeout_seconds")}), flush=True)
                continue

            if len(trial["samples"]) != 1 or child["outcome"] != "passed":
                raise RuntimeError("successful runner did not admit exactly one witnessed sample")
            sample = trial["samples"][0]
            try:
                runner.require_ready_witness(sample, args.ram_mib)
                different = [key for key in witness_keys if sample[key] != reference[key]]
            except (AssertionError, KeyError, ValueError) as error:
                attempt.update(outcome="invalid_witness", error=str(error))
                write_results(destination, results, labels)
                raise
            if different:
                attempt.update(outcome="invalid_witness", differing_fields=different)
                write_results(destination, results, labels)
                raise AssertionError(f"readiness witness drift: {different}")
            attempt.update(outcome="passed", sample=sample, all_reference_fields_equal=True)
            write_results(destination, results, labels)
            print(json.dumps({"pair": pair, "label": label, "outcome": "passed", "seconds": sample["seconds"]}), flush=True)

    results["campaign_complete"] = True
    results["all_successful_witnesses_match_reference"] = True
    write_results(destination, results, labels)


if __name__ == "__main__":
    main()

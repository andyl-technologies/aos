# SPDX-License-Identifier: Apache-2.0
"""Admit exact equal-completed-work pairs without claiming timing qualification.

This offline checker binds both receipt files to supplied immutable hashes and
matches each fixed row and seed. Raw roots alone only compare the same
fingerprint edition. Optional pinned complete-capture files compare all retained
RAM and state bytes independently of those roots, while physical origin and
model-complete producer compatibility remain outstanding obligations.

It retains CPU and wall costs separately. The existing producer reports
whole-work CPU as unavailable, so its rows remain
blocked for CPU comparisons. Three repetitions and uncontrolled host cache do
not establish a zero-regression confidence gate; this checker never issues one.
"""

import argparse
from fractions import Fraction
import hashlib
import importlib.util
import json
from pathlib import Path
import re


SCHEMA = "crucible.completed-campaign-throughput.v2"
TARGETS = (1, 2, 0)
PARALLEL = (1, 2, 4)
REPEATS = range(3)
RESOURCE_FIELDS = (
    "resident_peak_bytes", "backing_peak_bytes", "metadata_bytes",
    "staging_bytes", "paging_io_slots", "cpu_slots", "task_slots",
    "file_descriptors",
)
CPU_SCOPE = "whole admitted measurement ancestor through joined physical retirement"
ROLES = (
    "CRUCIBLE_PAGING_QEMU", "CRUCIBLE_PAGING_PLUGIN",
    "CRUCIBLE_PAGING_KERNEL", "CRUCIBLE_PAGING_INITRD", "CRUCIBLE_PAGING_ROOT",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, message, minimum=0):
    require(type(value) is int and minimum <= value <= 2**64 - 1, message)
    return value


def digest(value):
    require(isinstance(value, list) and len(value) == 32, "digest width")
    require(all(type(byte) is int and 0 <= byte <= 255 for byte in value), "digest bytes")
    return tuple(value)


def artifact_inventory(receipt):
    inventory = {}
    for artifact in receipt["pinned"]["artifact_digests"]:
        role = artifact["role"]
        require(role in ROLES and role not in inventory, "duplicate or foreign artifact role")
        inventory[role] = (integer(artifact["bytes"], "artifact extent", 1), digest(artifact["blake3"]))
    require(set(inventory) == set(ROLES), "incomplete artifact inventory")
    return inventory


def expected_seeds(target, parallel, repeat):
    start = (1000 + TARGETS.index(target) * len(REPEATS) * sum(PARALLEL)
             + len(REPEATS) * sum(PARALLEL[:PARALLEL.index(parallel)])
             + repeat * parallel)
    return set(range(start, start + parallel))


def admitted_resources(value):
    require(isinstance(value, dict) and set(value) == set(RESOURCE_FIELDS),
            "incomplete or foreign admitted resource vector")
    for field in RESOURCE_FIELDS:
        integer(value[field], f"admitted resource field {field}")


def row_inventory(receipt):
    require(receipt["schema"] == SCHEMA, "receipt schema")
    require(receipt["quanta_per_attempt"] == 32, "changed authored quanta")
    require(receipt["scenario_seeds"] == list(range(1000, 1063)), "changed seed corpus")
    inventory = {}
    used_seeds = set()
    for row in receipt["rows"]:
        key = (row["target_divisor"], row["parallel"], row["repeat"])
        require(all(type(value) is int for value in key), "row coordinates must be integers")
        require(key not in inventory, "duplicate row")
        require(key[0] in TARGETS and key[1] in PARALLEL and key[2] in REPEATS, "foreign row")
        require(not row["failures"], "failed row cannot become comparable completed work")
        require(integer(row["completed"], "completed count") == key[1], "partial completion")
        integer(row["elapsed_ns"], "positive complete wall interval", 1)
        samples = {}
        for sample in row["samples"]:
            seed = integer(sample["seed"], "seed")
            require(seed not in used_seeds, "reused seed cannot count as new completion")
            require(seed in range(1000, 1063), "foreign seed")
            used_seeds.add(seed)
            digest(sample["scenario"])
            digest(sample["fingerprint"])
            integer(sample["charged_physical_quanta"], "actual charged work", 1)
            integer(sample["emitted_signal_events"], "signal events")
            if sample["fault_work_items"] is not None:
                integer(sample["fault_work_items"], "fault work items")
            integer(sample["requested_target_bytes"], "requested target bytes")
            admitted_resources(sample["resources"])
            samples[seed] = sample
        require(len(samples) == key[1], "completed count lacks actual samples")
        require(set(samples) == expected_seeds(*key), "seed moved from fixed family")
        inventory[key] = (row, samples)
    expected = {
        (target, parallel, repeat)
        for target in TARGETS
        for parallel in PARALLEL
        for repeat in REPEATS
    }
    require(set(inventory) == expected and used_seeds == set(range(1000, 1063)), "incomplete fixed matrix")
    return inventory


def ratio(candidate, baseline):
    value = Fraction(candidate, baseline)
    return {"numerator": value.numerator, "denominator": value.denominator}


def compare(baseline, candidate, capture_pairs=None):
    state_consumer = None
    pairs = {}
    if capture_pairs is not None:
        require(set(capture_pairs) == {"schema", "pairs"}
                and capture_pairs["schema"] == "crucible.complete-capture-comparison-input.v1",
                "complete capture pair schema")
        for pair in capture_pairs["pairs"]:
            require(set(pair) == {"seed", "baseline", "candidate"}, "capture pair fields")
            seed = integer(pair["seed"], "capture pair seed")
            require(seed not in pairs, "duplicate capture pair seed")
            pairs[seed] = pair
        require(set(pairs) == set(range(1000, 1063)), "incomplete fixed capture pair corpus")
        spec = importlib.util.spec_from_file_location(
            "complete_state_witness",
            Path(__file__).with_name("ram-comparison-state-witness.py"),
        )
        state_consumer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(state_consumer)
    state_witnesses = []
    require(
        digest(baseline["scenario_corpus"]) == digest(candidate["scenario_corpus"]),
        "authored scenario corpus changed",
    )
    for field in ("host", "storage", "cpu_affinity"):
        for receipt in (baseline, candidate):
            value = receipt["pinned"][field]
            require(isinstance(value, str) and 0 < len(value.encode()) <= 1024,
                    "invalid host/storage profile label")
        require(baseline["pinned"][field] == candidate["pinned"][field], "host/storage profile changed")
    require(baseline["cache_scope"] == candidate["cache_scope"], "cache profile changed")
    reference_artifacts = artifact_inventory(baseline)
    candidate_artifacts = artifact_inventory(candidate)
    for role in ROLES[2:]:
        require(reference_artifacts[role] == candidate_artifacts[role], "guest artifact changed")
    reference_rows = row_inventory(baseline)
    candidate_rows = row_inventory(candidate)
    rows = []
    for key in reference_rows:
        reference, reference_samples = reference_rows[key]
        observed, observed_samples = candidate_rows[key]
        require(reference_samples.keys() == observed_samples.keys(), "seed moved between families")
        for seed, sample in reference_samples.items():
            peer = observed_samples[seed]
            fields = ("scenario", "charged_physical_quanta", "emitted_signal_events",
                      "fault_work_items", "resources", "requested_target_bytes")
            for field in fields:
                require(sample[field] == peer[field], f"same-seed actual work/state differs: {field}")
            if state_consumer is None:
                require(sample["fingerprint"] == peer["fingerprint"],
                        "same-seed actual work/state differs: fingerprint")
            else:
                pair = pairs[seed]
                require(pair["baseline"]["boundary"]["seed"] == seed
                        and pair["candidate"]["boundary"]["seed"] == seed,
                        "capture moved from its actual work seed")
                state_witnesses.append(state_consumer.compare_pair(pair["baseline"], pair["candidate"]))
        cpu = None
        reference_cpu = reference.get("completed_work_cpu_ns")
        observed_cpu = observed.get("completed_work_cpu_ns")
        for value in (reference_cpu, observed_cpu):
            if value is not None:
                integer(value, "positive completed-work CPU", 1)
        if reference_cpu is not None and observed_cpu is not None:
            require(
                baseline["completed_work_cpu_scope"] == candidate["completed_work_cpu_scope"],
                "CPU scope changed",
            )
            require(
                baseline["completed_work_cpu_scope"] == CPU_SCOPE,
                "incomplete CPU accounting scope",
            )
            cpu = ratio(
                integer(observed_cpu, "candidate CPU", 1),
                integer(reference_cpu, "baseline CPU", 1),
            )
        rows.append({
            "family": list(key),
            "completed": observed["completed"],
            "wall_ratio": ratio(observed["elapsed_ns"], reference["elapsed_ns"]),
            "cpu_ratio": cpu,
        })

    return {
        "schema": "crucible.completed-work-comparison.v1",
        "rows": rows,
        "cpu_comparison_ready": all(row["cpu_ratio"] is not None for row in rows),
        "performance_qualified": False,
        "comparison_scope": (
            "independent complete captured bytes, descriptive equal-work comparison only"
            if state_consumer
            else "same fingerprint edition, descriptive equal-work comparison only"
        ),
        "common_capture_bytes_ready": state_consumer is not None,
        "capture_witnesses": state_witnesses,
        "capture_physical_origin_verified": False,
        "fingerprint_edition_verified": False,
        "holds": [
            "fingerprint edition is not independently certified; cross-edition baseline "
            "requires an independent common complete-state/RAM witness",
            "retained capture bytes do not certify physical inventory/stopped origin "
            "or model-complete producer compatibility",
            "implicit firmware identity requires a separate actual input binding",
            "actual host observation/clock/CPU source evidence is not certified by labels",
            "fixed paired uncertainty and separate zero-margin family gates are not "
            "implemented by this descriptive checker",
            "cold/warm host storage is uncontrolled in the existing producer",
        ],
    }


def unique_fields(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def read_pinned(path, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "expected receipt SHA256")
    raw = path.read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == expected,
        "receipt identity differs from pinned baseline/candidate",
    )
    return json.loads(raw, object_pairs_hook=unique_fields)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for side in ("baseline", "candidate"):
        parser.add_argument(f"--{side}", type=Path, required=True)
        parser.add_argument(f"--{side}-sha256", required=True)
    parser.add_argument("--capture-pairs", type=Path)
    parser.add_argument("--capture-pairs-sha256")
    arguments = parser.parse_args()
    try:
        require((arguments.capture_pairs is None) == (arguments.capture_pairs_sha256 is None),
                "capture pair path and immutable pin must be supplied together")
        capture_pairs = (read_pinned(arguments.capture_pairs, arguments.capture_pairs_sha256)
                         if arguments.capture_pairs else None)
        result = compare(read_pinned(arguments.baseline, arguments.baseline_sha256),
                         read_pinned(arguments.candidate, arguments.candidate_sha256), capture_pairs)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"completed-work comparison: {error}\n")
    result["baseline_sha256"] = arguments.baseline_sha256
    result["candidate_sha256"] = arguments.candidate_sha256
    result["capture_pairs_sha256"] = arguments.capture_pairs_sha256
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

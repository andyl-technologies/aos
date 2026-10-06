# SPDX-License-Identifier: Apache-2.0
"""Authenticate equal-work paired timings without manufacturing a baseline.

The decision requires predeclared paired medians and marginal upper limits,
not a universal latency bound. All original samples and fixed marginal
uncertainty limits are retained.
The command accepts only retained store outputs and never executes benchmarks.
"""

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys

U64_MAX = 2**64 - 1
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 1024 * 1024
MEASUREMENT_BEGIN = "CRUCIBLE_CAMPAIGN_COMPLETED_MEASUREMENTS_BEGIN_V2"
MEASUREMENT_END = "CRUCIBLE_CAMPAIGN_COMPLETED_MEASUREMENTS_END_V2"
PAIR_COUNT = 8
CORPUS_COUNT = 3
HEX = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
STORE_NAME = re.compile(r"[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+\Z")
METRICS = tuple(
    f"corpus_{index}_{metric}"
    for index in range(CORPUS_COUNT)
    for metric in (
        "campaign_request_setup_ns", "campaign_planner_queue_ns",
        "hot_setup_ns", "hot_guest_continuation_ns", "exact_setup_ns",
        "exact_guest_continuation_ns",
    )
) + ("campaign_performance_case_elapsed_ns",)
CONDITION_KEYS = {
    "semantic_inputs", "toolchain", "native_configuration", "host_configuration",
    "cache_configuration", "measurement_fixture",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"{label}: unexpected fields")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path, maximum=MAX_ARTIFACT_BYTES):
    with Path(path).open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError(f"{path}: artifact exceeds byte bound")
    return data


def positive(value, label):
    if type(value) is not int or not 0 < value <= U64_MAX:
        raise ValueError(f"{label}: expected positive u64")
    return value


def one_number(serial, name):
    prefix = name + "="
    values = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or re.fullmatch(r"[0-9]+", values[0]) is None:
        raise ValueError(f"expected one measured {name} with a decimal value")
    return positive(int(values[0]), name)


def one_record(serial, name, maximum=MAX_RECORD_BYTES):
    values = re.findall(rf"^{re.escape(name)}=(.+)$", serial, re.MULTILINE)
    if len(values) != 1 or len(values[0].encode()) > maximum:
        raise ValueError(f"expected one bounded {name}")
    return values[0].encode()


def completed_measurements(serial):
    """Reads the one completed report without deduplicating live observations."""
    lines = serial.splitlines(keepends=True)
    begins = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == MEASUREMENT_BEGIN]
    ends = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == MEASUREMENT_END]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise ValueError("expected one complete final measurement frame")
    report = "".join(lines[begins[0] + 1:ends[0]])
    if not report or len(report.encode()) > MAX_ARTIFACT_BYTES:
        raise ValueError("completed measurement frame is empty or exceeds bound")
    return report


def read_fields(data):
    pairs = [line.split("=", 1) for line in data.decode().splitlines()]
    if not pairs or any(len(pair) != 2 for pair in pairs):
        raise ValueError("expected nonempty key=value artifact")
    return unique_object(pairs)


def authenticate(path, expected_digest, maximum=MAX_ARTIFACT_BYTES):
    if Path(path).is_symlink():
        raise ValueError(f"{path}: retain actual artifact bytes instead of a symlink")
    if not isinstance(expected_digest, str) or not HEX.fullmatch(expected_digest):
        raise ValueError("invalid artifact digest")
    data = bounded_read(path, maximum)
    if digest(data) != expected_digest:
        raise ValueError(f"{path}: retained artifact changed identity")
    return data


def _member(member, revision, plan, reference_host, store_directory):
    fields(member, {
        "output", "source_manifest_sha256", "result_sha256", "serial_sha256",
        "host_sha256", "work_record_sha256",
    }, "sample member")
    output = Path(member["output"])
    if output.parent != store_directory or not STORE_NAME.fullmatch(output.name) or output.is_symlink():
        raise ValueError("sample must name a canonical whole store output")
    result = authenticate(output / "result", member["result_sha256"])
    if result.decode().splitlines()[0] != "PASS":
        raise ValueError("sample is not PASS")
    serial = authenticate(output / "serial.log", member["serial_sha256"]).decode()
    host = read_fields(authenticate(output / "host-reference.env", member["host_sha256"]))
    for key, value in reference_host.items():
        if key != "schema" and host.get(key) != value:
            raise ValueError(f"sample host differs: {key}")
    if not re.fullmatch(r"[0-9,-]+", host.get("host_allowed_cpus", "")):
        raise ValueError("missing actual CPU affinity")
    if not re.fullmatch(r"[0-9a-f-]{36}", host.get("host_boot_id", "")):
        raise ValueError("missing actual host boot identity")

    source = decode_json(authenticate(
        output / "performance-source-manifest.json", member["source_manifest_sha256"]
    ))
    fields(source, {"schema", "revision", "sample_id", "conditions", "production"}, "source manifest")
    if source["schema"] != "crucible.campaign-performance.source.v2" or source["revision"] != revision:
        raise ValueError("sample revision/source schema differs")
    if not re.fullmatch(r"[0-9a-f]{32}", source["sample_id"]):
        raise ValueError("invalid sample identity")
    fields(source["conditions"], CONDITION_KEYS, "comparison conditions")
    if any(not isinstance(value, str) or not HEX.fullmatch(value) for value in source["conditions"].values()):
        raise ValueError("invalid comparison-condition identity")
    if source["conditions"] != plan["conditions"]:
        raise ValueError("sample input/toolchain/configuration conditions differ")
    if source["production"] != plan["production"][revision]:
        raise ValueError("sample does not authenticate its own measured production revision")
    report = completed_measurements(serial)
    actual_id = one_record(report, "campaign_performance_sample_id").decode()
    if actual_id != source["sample_id"]:
        raise ValueError("sample identity did not reach the actual performance VM")
    provenance = decode_json(one_record(serial, "campaign_performance_provenance_json", MAX_SOURCE_MANIFEST_BYTES))
    if provenance != source:
        raise ValueError("retained source manifest differs from actual VM provenance")
    for name, value in (
        ("campaign_guest_cpu_affinity", "0"),
        ("campaign_planner_supervisor", "packaged-process"),
        ("campaign_blob_backend", "sqlite-store-graph"),
        ("campaign_short_branch_boundary", "two-node-pending-selectable"),
    ):
        if one_record(report, name).decode() != value:
            raise ValueError(f"original producer condition differs: {name}")

    timings = {name: one_number(report, name) for name in METRICS}
    planner = sum(timings[f"corpus_{index}_campaign_planner_queue_ns"] for index in range(CORPUS_COUNT))
    guest = sum(timings[f"corpus_{index}_hot_guest_continuation_ns"] for index in range(CORPUS_COUNT))
    if max(planner, guest) > U64_MAX:
        raise ValueError("measured total overflow")
    if planner != one_number(report, "campaign_planner_queue_total_ns") or guest != one_number(report, "hot_guest_continuation_total_ns"):
        raise ValueError("measured phase total differs")
    if planner * 100 >= guest * 5:
        raise ValueError("sample fails independent strict five-percent requirement")
    if planner * 1_000_000 > guest * plan["max_planner_queue_ratio_ppm"]:
        raise ValueError("sample exceeds pinned ratio ceiling")

    hashes = member["work_record_sha256"]
    if not isinstance(hashes, list) or len(hashes) != CORPUS_COUNT:
        raise ValueError("missing work record digest")
    work = []
    for index, expected_hash in enumerate(hashes):
        data = authenticate(output / f"corpus-{index}-work.json", expected_hash, MAX_RECORD_BYTES)
        actual = one_record(report, f"corpus_{index}_campaign_work_json")
        if data != actual:
            raise ValueError("retained work differs from actual VM record")
        record = decode_json(data)
        fields(record, {"schema", "corpus", "planner", "hot", "exact"}, "work record")
        if record["schema"] != "crucible.campaign-performance.work.v2" or type(record["corpus"]) is not int or record["corpus"] != index:
            raise ValueError("work record schema/corpus differs")
        if record["planner"]["queue_attempts"] != 1 or not record["hot"]["outcomes"] or not record["exact"]["outcomes"]:
            raise ValueError("work record lacks actual planner/guest work")
        work.append(data)
    return {"output": str(output), "sample_id": actual_id, "host": host, "timings": timings, "work": work}


def ratio_json(ratio):
    return {"numerator": ratio.numerator, "denominator": ratio.denominator}


def compare(comparison_path, decision_plan_path, reference_host_path, *, current_source_path=None, current_serial_path=None, _store_directory=Path("/nix/store")):
    """Authenticates paired artifacts and returns the bounded timing decision.

    Private store-directory injection is only for finite parser controls. The
    public command fixes /nix/store and has no alternative artifact-root flag.
    """
    comparison = decode_json(bounded_read(comparison_path))
    fields(comparison, {
        "schema", "reference_revision", "candidate_revision",
        "reference_host_profile_sha256", "decision_plan_sha256",
        "max_planner_queue_ratio_ppm", "pairs",
    }, "comparison")
    if comparison["schema"] != "crucible.campaign-performance.comparison.v2":
        raise ValueError("only authenticated v2 paired evidence is supported")
    revisions = [comparison[role + "_revision"] for role in ("reference", "candidate")]
    if any(not isinstance(value, str) or not REVISION.fullmatch(value) for value in revisions):
        raise ValueError("invalid frozen revision")
    plan = decode_json(authenticate(decision_plan_path, comparison["decision_plan_sha256"]))
    fields(plan, {"schema", "method", "required_metrics", "unaffected_metrics", "conditions", "production", "max_planner_queue_ratio_ppm"}, "decision plan")
    if plan["schema"] != "crucible.campaign-performance.decision.v2" or plan["method"] != "paired-median-eight-marginal-upper-at-most-one-v2":
        raise ValueError("unsupported predeclared decision method")
    required = plan["required_metrics"]
    unaffected = plan["unaffected_metrics"]
    if not isinstance(required, list) or not required or len(required) != len(set(required)) or not set(required) <= set(METRICS):
        raise ValueError("invalid required metric vector")
    if not isinstance(unaffected, dict) or set(unaffected) != set(METRICS) - set(required) or any(not isinstance(value, str) or not value for value in unaffected.values()):
        raise ValueError("unaffected paths require explicit source-backed scope")
    fields(plan["production"], set(revisions), "revision-specific production manifests")
    for revision in revisions:
        production = plan["production"][revision]
        if not isinstance(production, dict) or not production or any(not isinstance(path, str) or not path or not isinstance(value, str) or not HEX.fullmatch(value) for path, value in production.items()):
            raise ValueError("invalid revision-specific production source identities")
    reference_sources, candidate_sources = (plan["production"][revision] for revision in revisions)
    native_keys = {
        path for path in set(reference_sources) | set(candidate_sources)
        if path.startswith("native/") or path.startswith("crates/crucible-qemu-plugin/")
    }
    if any(reference_sources.get(path) != candidate_sources.get(path) for path in native_keys):
        raise ValueError("native changes require separate authenticated None-path and equal-byte console timing; campaign medians cannot qualify them")
    ceiling = positive(plan["max_planner_queue_ratio_ppm"], "ratio ceiling")
    if ceiling >= 50_000 or comparison["max_planner_queue_ratio_ppm"] != ceiling:
        raise ValueError("invalid or changed pinned ratio ceiling")
    if current_source_path is not None:
        current = decode_json(bounded_read(current_source_path, MAX_SOURCE_MANIFEST_BYTES))
        fields(current, {"schema", "revision", "sample_id", "conditions", "production"}, "current consumer source")
        if current["schema"] != "crucible.campaign-performance.source.v2" or current["production"] != plan["production"][revisions[1]] or current["conditions"] != plan["conditions"]:
            raise ValueError("current consumer source/configuration differs from measured candidate")
    if current_serial_path is not None:
        report = completed_measurements(bounded_read(current_serial_path).decode())
        planner = sum(one_number(report, f"corpus_{index}_campaign_planner_queue_ns") for index in range(CORPUS_COUNT))
        guest = sum(one_number(report, f"corpus_{index}_hot_guest_continuation_ns") for index in range(CORPUS_COUNT))
        if max(planner, guest) > U64_MAX or planner != one_number(report, "campaign_planner_queue_total_ns") or guest != one_number(report, "hot_guest_continuation_total_ns"):
            raise ValueError("current scaling total differs or overflows")
        if planner * 100 >= guest * 5 or planner * 1_000_000 > guest * ceiling:
            raise ValueError("current scaling exceeds original strict ratio/ratchet")
    reference_host = read_fields(authenticate(reference_host_path, comparison["reference_host_profile_sha256"]))
    pairs = comparison["pairs"]
    if not isinstance(pairs, list) or len(pairs) != PAIR_COUNT:
        raise ValueError("exactly eight paired samples are required")

    identities = set()
    outputs = set()
    ratios = {name: [] for name in required}
    raw = []
    fixed_host = None
    fixed_work = None
    for ordinal, pair in enumerate(pairs):
        fields(pair, {"ordinal", "order", "reference", "candidate"}, "pair")
        if type(pair["ordinal"]) is not int or pair["ordinal"] != ordinal or pair["order"] != ("AB" if ordinal % 2 == 0 else "BA"):
            raise ValueError("pair order differs from predeclared AB/BA sequence")
        members = [_member(pair[role], revision, plan, reference_host, _store_directory) for role, revision in zip(("reference", "candidate"), revisions)]
        for member in members:
            if member["sample_id"] in identities or member["output"] in outputs:
                raise ValueError("cached/duplicate actual sample identity or output")
            if fixed_work is None:
                fixed_work = member["work"]
            elif member["work"] != fixed_work:
                raise ValueError("canonical work differs across the fixed repeated corpus")
            identities.add(member["sample_id"])
            outputs.add(member["output"])
            if fixed_host is None:
                fixed_host = member["host"]
            elif member["host"] != fixed_host:
                raise ValueError("actual host/affinity/boot conditions differ across samples")
        reference, candidate = members
        if reference["work"] != candidate["work"]:
            raise ValueError("paired canonical work differs")
        for name in required:
            ratios[name].append(Fraction(candidate["timings"][name], reference["timings"][name]))
        raw.append({"ordinal": ordinal, "order": pair["order"], **{role: {"output": member["output"], "sample_id": member["sample_id"], "timings": member["timings"]} for role, member in zip(("reference", "candidate"), members)}})

    throughput = []
    for pair in raw:
        samples = {}
        for role in ("reference", "candidate"):
            samples[role] = [
                ratio_json(Fraction(
                    len(decode_json(fixed_work[index])["hot"]["outcomes"]),
                    pair[role]["timings"][f"corpus_{index}_hot_guest_continuation_ns"],
                ))
                for index in range(CORPUS_COUNT)
            ]
        throughput.append({"ordinal": pair["ordinal"], "completed_quanta_per_ns": samples})

    reports = {}
    slower = []
    uncertain = []
    for name, values in ratios.items():
        ordered = sorted(values)
        median = (ordered[3] + ordered[4]) / 2
        if median > 1:
            slower.append(name)
        if ordered[6] > 1:
            uncertain.append(name)
        reports[name] = {
            "raw_paired_ratios": [ratio_json(value) for value in values],
            "paired_median": ratio_json(median),
            "one_sided_upper_96_484375_percent": ratio_json(ordered[6]),
            "two_sided_99_21875_percent": [ratio_json(ordered[0]), ratio_json(ordered[7])],
            "upper_limit_exceeds_one": ordered[6] > 1,
        }
    return {
        "schema": "crucible.campaign-performance.decision-result.v2",
        "decision": "REFUSED" if slower else "INCONCLUSIVE" if uncertain else "ACCEPTED_MARGINAL_NO_REGRESSION",
        "slower_required_medians": slower, "metrics": reports, "raw_pairs": raw,
        "required_upper_limits_exceeding_one": uncertain,
        "unaffected_metrics": unaffected, "equal_work_guest_throughput": throughput,
        "limits": "Marginal order-statistic limits assume independent stationary pairs; no universal, mean, tail, or simultaneous-vector guarantee.",
    }


def decision_exit_code(report):
    """Accepts only the predeclared median-and-upper-limit decision."""
    return 0 if report["decision"] == "ACCEPTED_MARGINAL_NO_REGRESSION" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("comparison", type=Path)
    parser.add_argument("decision_plan", type=Path)
    parser.add_argument("reference_host", type=Path)
    parser.add_argument("--current-source", type=Path)
    parser.add_argument("--current-serial", type=Path)
    args = parser.parse_args()
    try:
        report = compare(args.comparison, args.decision_plan, args.reference_host, current_source_path=args.current_source, current_serial_path=args.current_serial)
        print(json.dumps(report, sort_keys=True, indent=2))
        return decision_exit_code(report)
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, f"campaign paired performance: {error}\n")


if __name__ == "__main__":
    sys.exit(main())

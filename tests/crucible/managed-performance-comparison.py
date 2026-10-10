"""Compare repeated measurements under the same declared experiment contract.

These checks require real receipts from both builds. Historical measurements
with another timing interval or host/storage profile cannot serve as a baseline.
"""

import math
import re
import statistics

SCHEMA = "crucible.managed-performance-comparison.v1"


def checked_groups(receipt):
    """Validate provenance and group positive timings by their workload."""
    if receipt.get("schema") != SCHEMA:
        raise ValueError("unsupported managed performance receipt")
    profile = receipt.get("profile", {})
    if not isinstance(profile, dict):
        raise ValueError("measurement profile must name host, storage and affinity")
    if any(not isinstance(profile.get(key), str) or not profile[key].strip()
           for key in ("host", "storage", "cpu_affinity")):
        raise ValueError("baseline comparison requires a declared host/storage/affinity profile")
    timing_contract = receipt.get("timing_contract")
    if (not receipt.get("producer") or not receipt.get("inputs")
            or not isinstance(timing_contract, str) or not timing_contract.strip()):
        raise ValueError("receipt lacks content-bound inputs, producer or timing contract")
    for field in ("producer", "inputs"):
        values = receipt[field]
        if not isinstance(values, dict) or not values or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in values.values()
        ):
            raise ValueError(f"{field} must contain actual content digests")
    groups = {}
    for sample in receipt.get("samples", []):
        if any(sample.get(key) is not True for key in
               ("accepted_assignment", "managed_owner", "native_cleanup")):
            raise ValueError("sample lacks accepted ownership and physical cleanup")
        elapsed = sample.get("seconds")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (float, int)):
            raise ValueError("timing must be numeric")
        if not math.isfinite(elapsed) or elapsed <= 0:
            raise ValueError("timing must be finite and positive")
        shape = (sample.get("workload"), sample.get("ram_mib"))
        if (not isinstance(shape[0], str) or not shape[0].strip()
                or isinstance(shape[1], bool) or not isinstance(shape[1], int) or shape[1] <= 0):
            raise ValueError("sample lacks its authored workload shape")
        groups.setdefault(shape, []).append(elapsed)
    if not groups or any(len(values) < 2 for values in groups.values()):
        raise ValueError("each workload requires repeated actual measurements")
    return groups


def compare_no_regression(baseline, candidate):
    """Reject unmatched experiments and increased median or maximum latency."""
    previous = checked_groups(baseline)
    current = checked_groups(candidate)
    for field in ("profile", "inputs", "timing_contract"):
        if baseline[field] != candidate[field]:
            raise ValueError(f"performance baseline differs in {field}")
    if previous.keys() != current.keys():
        raise ValueError("performance baseline has another workload set")
    rows = []
    for shape in sorted(previous):
        old, new = previous[shape], current[shape]
        if len(old) != len(new):
            raise ValueError("performance baseline has another repeat count")
        old_median, new_median = statistics.median(old), statistics.median(new)
        old_maximum, new_maximum = max(old), max(new)
        if new_median > old_median or new_maximum > old_maximum:
            raise AssertionError(f"performance regression for {shape}: median {old_median} -> {new_median}, maximum {old_maximum} -> {new_maximum}")
        rows.append({
            "workload": shape[0], "ram_mib": shape[1], "repeat_count": len(old),
            "baseline_median_seconds": old_median, "candidate_median_seconds": new_median,
            "baseline_maximum_seconds": old_maximum, "candidate_maximum_seconds": new_maximum,
        })
    return rows

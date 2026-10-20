"""Prepare a reviewable campaign performance baseline from a scaling gate.

The output is a candidate fixture, not an approval. Keep the raw scaling result
and logs so reviewers can independently verify every measured value and digest.
"""

import argparse
import hashlib
import pathlib
import re
import sys


REFERENCE_PROFILE = (
    pathlib.Path(__file__).parent
    / "fixtures/campaign-performance-reference-host-v1.env"
)
U64_MAX = 2**64 - 1


def read_fields(path):
    lines = path.read_text().splitlines()
    pairs = [line.split("=", 1) for line in lines]
    if not lines or any(len(pair) != 2 for pair in pairs):
        raise ValueError(f"{path}: expected nonempty key=value lines")
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError(f"{path}: duplicate field")
    return fields


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def one_positive_number(serial, name):
    values = re.findall(rf"^{re.escape(name)}=([0-9]+)$", serial, re.MULTILINE)
    if len(values) != 1:
        raise ValueError(f"expected one {name} in scaling serial log; found {len(values)}")
    value = int(values[0])
    if not 0 < value <= U64_MAX:
        raise ValueError(f"{name} is outside the positive u64 range")
    return value


def require_serial_line(serial, line):
    if len(re.findall(rf"^{re.escape(line)}$", serial, re.MULTILINE)) != 1:
        raise ValueError(f"expected one {line!r} in scaling serial log")


def candidate(scaling_output, ceiling):
    result_path = scaling_output / "result"
    serial_path = scaling_output / "serial.log"
    host_path = scaling_output / "host-reference.env"

    if result_path.read_text().splitlines()[0] != "PASS":
        raise ValueError("scaling gate result is not PASS")
    serial = serial_path.read_text()
    expected = read_fields(REFERENCE_PROFILE)
    observed = read_fields(host_path)
    expected_keys = {
        "schema", "host_name", "host_cpu_model", "host_cpu_family",
        "host_cpu_model_number", "host_cpu_stepping", "host_cpu_microcode",
        "host_kernel_release", "host_pinned_cpu",
    }
    if (
        set(expected) != expected_keys
        or expected["schema"] != "crucible.campaign-performance.reference-host.v1"
    ):
        raise ValueError("reference host profile has an unexpected schema")
    for key in expected_keys - {"schema"}:
        if observed.get(key) != expected[key]:
            raise ValueError(f"observed host {key} differs from the pinned profile")
    if not re.fullmatch(r"[0-9,-]+", observed.get("host_allowed_cpus", "")):
        raise ValueError("observed host affinity is missing or malformed")
    if not re.fullmatch(r"[0-9a-f-]{36}", observed.get("host_boot_id", "")):
        raise ValueError("observed host boot ID is missing or malformed")

    for line in (
        "gate=gate:hot-fork-scaling",
        "campaign_guest_cpu_affinity=0",
        "campaign_planner_supervisor=packaged-process",
        "campaign_blob_backend=sqlite-store-graph",
        "campaign_short_branch_boundary=two-node-pending-selectable",
    ):
        require_serial_line(serial, line)

    planner = sum(
        one_positive_number(serial, f"corpus_{index}_campaign_planner_queue_ns")
        for index in range(3)
    )
    guest = sum(
        one_positive_number(serial, f"corpus_{index}_hot_guest_continuation_ns")
        for index in range(3)
    )
    if planner > U64_MAX or guest > U64_MAX:
        raise ValueError("measured totals exceed the u64 range")
    if planner != one_positive_number(serial, "campaign_planner_queue_total_ns"):
        raise ValueError("planner/queue total disagrees with per-corpus samples")
    if guest != one_positive_number(serial, "hot_guest_continuation_total_ns"):
        raise ValueError("guest continuation total disagrees with per-corpus samples")
    if planner * 100 >= guest * 5:
        raise ValueError("measured planner/queue time does not meet the strict 5% limit")
    if not 0 < ceiling < 50_000 or planner * 1_000_000 > guest * ceiling:
        raise ValueError("reviewed ratio ceiling is invalid or below the measured ratio")

    return (
        "schema=crucible.campaign-performance.baseline.v1\n"
        f"reference_host_profile_sha256={sha256(REFERENCE_PROFILE)}\n"
        f"reference_scaling_result_sha256={sha256(result_path)}\n"
        f"reference_scaling_serial_sha256={sha256(serial_path)}\n"
        f"reference_scaling_host_sha256={sha256(host_path)}\n"
        f"baseline_planner_queue_ns={planner}\n"
        f"baseline_guest_continuation_ns={guest}\n"
        f"max_planner_queue_ratio_ppm={ceiling}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scaling_output", type=pathlib.Path)
    parser.add_argument("--ratio-ceiling-ppm", required=True, type=int)
    args = parser.parse_args()
    try:
        sys.stdout.write(candidate(args.scaling_output, args.ratio_ceiling_ppm))
    except (OSError, IndexError, ValueError) as error:
        parser.exit(1, f"campaign performance baseline: {error}\n")


if __name__ == "__main__":
    main()

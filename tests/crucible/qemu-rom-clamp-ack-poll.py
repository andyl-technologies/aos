"""Checks exact ROM clamp equivalence; host duration is advisory, not a gate."""

import json
from pathlib import Path
import sys

FIELDS = {
    "completed_quantum_clamps",
    "step_ps",
    "clamp_guard_ms",
    "guest_profile",
    "owned_cleanup",
    "initial_ps",
    "final_ps",
    "initial_raw",
    "final_raw",
    "experiment_ack_poll_us",
    "host_drive_elapsed_us",
    "qemu_cpu_time",
}


def bounded_text(path, maximum):
    with Path(path).open() as source:
        text = source.read(maximum + 1)
    if len(text.encode("utf-8")) > maximum:
        raise ValueError("input exceeds retained limit")
    return text


def read_result(text):
    if len(text.encode("utf-8")) > 16384:
        raise ValueError("result exceeds 16 KiB")
    lines = text.splitlines()
    if lines.count("PASS") != 1:
        raise ValueError("missing or repeated PASS")
    result = {}
    for line in lines:
        if line == "PASS":
            continue
        key, value = line.split("=", 1)
        if key not in FIELDS or key in result:
            raise ValueError("unknown or repeated result field")
        result[key] = value
    if set(result) != FIELDS:
        raise ValueError("incomplete result")
    for key in FIELDS - {"guest_profile", "owned_cleanup", "qemu_cpu_time"}:
        if not result[key].isascii() or not result[key].isdecimal():
            raise ValueError("nondecimal result")
        limit = 128 if key == "host_drive_elapsed_us" else 64
        if len(result[key]) > 39 or int(result[key]) >= 2 ** limit:
            raise ValueError("numeric result exceeds its scalar width")
        result[key] = int(result[key])
    expected = {
        "completed_quantum_clamps": 20000,
        "step_ps": 1000,
        "clamp_guard_ms": 1000,
        "guest_profile": "busy-firmware-no-network",
        "owned_cleanup": "complete",
        "qemu_cpu_time": "unavailable",
    }
    if any(result[key] != value for key, value in expected.items()):
        raise ValueError("changed workload or guard")
    if result["final_ps"] - result["initial_ps"] != 20000000:
        raise ValueError("changed logical grant total")
    if result["final_raw"] - result["initial_raw"] != 400000:
        raise ValueError("raw retirement does not match the selected 50ps calibration")
    return result


def compare(baseline, candidate):
    if baseline["experiment_ack_poll_us"] != 1000:
        raise ValueError("wrong baseline interval")
    if candidate["experiment_ack_poll_us"] != 100:
        raise ValueError("wrong candidate interval")
    canonical = FIELDS - {"experiment_ack_poll_us", "host_drive_elapsed_us"}
    if any(baseline[key] != candidate[key] for key in canonical):
        raise ValueError("fresh runs changed canonical coordinates or cleanup")
    return {
        "baseline_host_drive_us": baseline["host_drive_elapsed_us"],
        "candidate_host_drive_us": candidate["host_drive_elapsed_us"],
        "canonical_results_equal": True,
        "qemu_cpu_time": "unavailable",
        "scope": "fresh busy-ROM ACK polling only; no whole-replay attribution",
    }


def serial_results(serial):
    results = []
    previous_end = -1
    for mode in ("baseline", "ack-poll-100us"):
        begin = f"CRUCIBLE_ACK_POLL_RESULT_BEGIN {mode}\n"
        end = f"CRUCIBLE_ACK_POLL_RESULT_END {mode}\n"
        if serial.count(begin) != 1 or serial.count(end) != 1:
            raise ValueError("missing or repeated result delimiters")
        start, finish = serial.index(begin), serial.index(end)
        if not previous_end < start < finish:
            raise ValueError("reversed or overlapping result pairs")
        result = serial[start + len(begin):finish]
        results.append((mode, result, read_result(result)))
        previous_end = finish + len(end) - 1
    return results


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--serial":
        serial = bounded_text(sys.argv[2], 16 * 1024 * 1024)
        pairs = serial_results(serial)
        results = [parsed for _, _, parsed in pairs]
        for mode, result, _ in pairs:
            Path(sys.argv[3], f"{mode}.result").write_text(result)
    elif len(sys.argv) == 3:
        results = [read_result(bounded_text(path, 16384)) for path in sys.argv[1:]]
    else:
        raise ValueError("expected two result files or --serial SERIAL OUTPUT")
    summary = compare(*results)
    encoded = json.dumps(summary, sort_keys=True) + "\n"
    if len(sys.argv) == 4:
        Path(sys.argv[3], "comparison.json").write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()

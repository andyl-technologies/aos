"""Checks canonical Linux boot equivalence; host duration is advisory."""

import json
from pathlib import Path
import sys

NUMBERS = {
    "experiment_ack_poll_us",
    "host_segment_elapsed_us",
    "grants",
    "step_ps",
    "initial_ps",
    "final_scheduler_ps",
    "final_physical_ps",
    "initial_raw",
    "final_raw",
    "control_returns",
    "projected_grants",
    "clamp_guard_ms",
    "advance_guard_s",
}
DIGESTS = {"transcript_blake3", "initial_fingerprint", "final_fingerprint"}
FIXED = {
    "guest_profile": "production-diskless-linux-four-vcpu",
    "readiness_idle_wake_equal": "true",
    "canonical_results_equal": "true",
    "owned_cleanup": "complete",
    "qemu_cpu_time": "unavailable",
}
FIELDS = NUMBERS | DIGESTS | set(FIXED)


def bounded_text(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input exceeds retained bound")
    return data.decode("ascii")


def result(text):
    if len(text.encode("ascii")) > 16384:
        raise ValueError("result exceeds 16 KiB")
    lines = text.splitlines()
    if lines.count("PASS") != 1:
        raise ValueError("missing or repeated PASS")
    values = {}
    for line in lines:
        if line == "PASS":
            continue
        key, value = line.split("=", 1)
        if key not in FIELDS or key in values:
            raise ValueError("unknown or repeated field")
        values[key] = value
    if set(values) != FIELDS or any(
        values[key] != value for key, value in FIXED.items()
    ):
        raise ValueError("incomplete or changed Linux profile")
    for key in NUMBERS:
        value = values[key]
        width = 128 if key == "host_segment_elapsed_us" else 64
        if (
            not value.isascii()
            or not value.isdecimal()
            or len(value) > 39
            or int(value) >= 2 ** width
        ):
            raise ValueError("noncanonical or oversized number")
        if str(int(value)) != value:
            raise ValueError("noncanonical number")
        values[key] = int(value)
    for key in DIGESTS:
        if len(values[key]) != 64 or any(
            character not in "0123456789abcdef" for character in values[key]
        ):
            raise ValueError("invalid canonical digest")
    required = {
        "grants": 20000,
        "step_ps": 10000000,
        "initial_ps": 8000000,
        "final_scheduler_ps": 200008000000,
        "clamp_guard_ms": 1000,
        "advance_guard_s": 300,
    }
    if any(values[key] != value for key, value in required.items()):
        raise ValueError("changed grants or original guard")
    if not 20000 <= values["control_returns"] <= 40000:
        raise ValueError("control return count outside finite segment")
    if not 0 <= values["projected_grants"] <= 20000:
        raise ValueError("invalid projection count")
    if not values["initial_ps"] < values["final_physical_ps"] <= values["final_scheduler_ps"]:
        raise ValueError("invalid physical coordinate")
    if values["final_physical_ps"] < values["final_scheduler_ps"] and not values["projected_grants"]:
        raise ValueError("unproven projection")
    if values["final_raw"] <= values["initial_raw"]:
        raise ValueError("Linux did not retire instructions")
    return values


def pair(text):
    results = []
    previous = -1
    for name in ("baseline", "ack-poll-100us"):
        begin = f"CRUCIBLE_LINUX_ACK_POLL_RESULT_BEGIN {name}\n"
        end = f"CRUCIBLE_LINUX_ACK_POLL_RESULT_END {name}\n"
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ValueError("missing or repeated pair delimiter")
        start, finish = text.index(begin), text.index(end)
        if not previous < start < finish:
            raise ValueError("reversed or overlapping pair")
        body = text[start + len(begin):finish]
        results.append((name, body, result(body)))
        previous = finish + len(end) - 1
    baseline, candidate = (item[2] for item in results)
    if (
        baseline["experiment_ack_poll_us"] != 1000
        or candidate["experiment_ack_poll_us"] != 100
    ):
        raise ValueError("wrong experiment intervals")
    canonical = FIELDS - {"experiment_ack_poll_us", "host_segment_elapsed_us"}
    if any(baseline[key] != candidate[key] for key in canonical):
        raise ValueError("fresh Linux runs changed canonical evidence")
    return results


def main():
    serial_mode = len(sys.argv) == 4 and sys.argv[1] == "--serial"
    if serial_mode:
        pairs = pair(bounded_text(sys.argv[2], 16 * 1024 * 1024))
        for name, body, _ in pairs:
            Path(sys.argv[3], f"{name}.result").write_text(body)
    elif len(sys.argv) == 2:
        pairs = pair(bounded_text(sys.argv[1], 32768))
    else:
        raise ValueError("expected RESULT or --serial SERIAL OUTPUT")
    baseline, candidate = (item[2] for item in pairs)
    summary = {
        "baseline_host_segment_us": baseline["host_segment_elapsed_us"],
        "candidate_host_segment_us": candidate["host_segment_elapsed_us"],
        "canonical_results_equal": True,
        "scope": "one fresh Linux boot grant segment; no production optimization or replay attribution",
        "qemu_cpu_time": "unavailable",
    }
    encoded = json.dumps(summary, sort_keys=True) + "\n"
    if serial_mode:
        Path(sys.argv[3], "comparison.json").write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()

"""Summarize bounded store stages from a real campaign diagnostic run.

Invoke with the source-built Python from the AOS development shell. This
reader measures evidence; it does not admit a campaign or qualify the gate.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


MAX_LINE_BYTES = 2 * 1024 * 1024
PHASES = {
    "initialization",
    "publish-request",
    "discover",
    "setup",
    "planner-preflight",
    "planner-component",
    "planner",
}
OPERATIONS = {"contains", "open-read-handle", "put-single", "put-batch", "stream-read"}
SAMPLE_REQUESTS = {1, 16, 64, 256}


def summarize(path):
    """Read exact counters without retaining object identities or plan records."""
    digest = hashlib.sha256()
    plans = hashlib.sha256()
    plan_count = 0
    totals = {}
    samples = {}
    latest = {}
    component = {"calls": 0, "nanoseconds": 0, "maximum_nanoseconds": 0}
    terminal = None
    passed = False

    with path.open("rb") as evidence:
        while raw := evidence.readline(MAX_LINE_BYTES + 1):
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError("diagnostic line exceeds the bounded reader")
            digest.update(raw)
            line = raw.decode("utf-8").strip()
            if line.startswith("campaign_store_profile "):
                header, body = line.split(" measurements=", 1)
                fields = dict(field.split("=", 1) for field in header.split()[1:])
                request = int(fields["request"])
                phase = fields["phase"]
                if phase not in PHASES:
                    raise ValueError(f"unknown store stage: {phase}")
                measured = json.loads(body)
                operations = measured["operations"]
                stage = totals.setdefault(phase, {})
                for operation, counters in operations.items():
                    if operation not in OPERATIONS:
                        raise ValueError(f"unknown store operation: {operation}")
                    accumulated = stage.setdefault(
                        operation, {"calls": 0, "bytes": 0, "nanoseconds": 0}
                    )
                    for name in accumulated:
                        accumulated[name] += counters[name]
                compact = {
                    "operations": operations,
                    "listed_read_ids": len(measured["immutable_reads"]),
                    "unlisted_reads": measured.get("unlisted_immutable_reads", 0),
                    "maximum_reads_of_one_id": max(
                        measured["immutable_reads"].values(), default=0
                    ),
                }
                latest[phase] = {"request": request, **compact}
                if request in SAMPLE_REQUESTS:
                    samples.setdefault(str(request), {})[phase] = compact
            elif line.startswith("campaign_component_profile "):
                fields = dict(field.split("=", 1) for field in line.split()[1:])
                if fields["succeeded"] != "true":
                    raise ValueError("real planner component failed")
                elapsed = int(fields["nanoseconds"])
                component["calls"] += 1
                component["nanoseconds"] += elapsed
                component["maximum_nanoseconds"] = max(
                    component["maximum_nanoseconds"], elapsed
                )
            elif line.startswith("campaign_million_plan_id "):
                fields = dict(field.split("=", 1) for field in line.split()[1:])
                if int(fields["request"]) != plan_count + 1:
                    raise ValueError("nonconsecutive native planner step evidence")
                plan_count += 1
                plans.update((fields["step"] + "\n").encode("utf-8"))
            elif line.startswith("campaign_million_profile "):
                if terminal is not None:
                    raise ValueError("multiple terminal corpus profiles")
                terminal = {
                    key: int(value)
                    for key, value in (
                        field.split("=", 1) for field in line.split()[1:]
                    )
                }
            elif re.fullmatch(r"test result: ok\. 1 passed; 0 failed;.*", line):
                passed = True

    if not passed or terminal is None:
        raise ValueError("diagnostic corpus did not complete successfully")
    if plan_count != terminal["requests"]:
        raise ValueError("missing exact planner step identities")
    if component["calls"] != terminal["requests"]:
        raise ValueError("missing real component measurements")
    return {
        "log_sha256": digest.hexdigest(),
        "plan_count": plan_count,
        "ordered_plan_ids_sha256": plans.hexdigest(),
        "terminal": terminal,
        "component": component,
        "stage_totals": totals,
        "samples": samples,
        "latest": latest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.log), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

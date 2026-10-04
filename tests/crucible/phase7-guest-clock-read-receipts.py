"""Binds bounded host clock-read evidence to genuine native ownership receipts."""

import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path

MAX_EVIDENCE = 64 * 1024


def read_evidence(stream):
    raw = stream.read(MAX_EVIDENCE + 1)
    if len(raw) > MAX_EVIDENCE:
        raise ValueError("clock-read evidence exceeds 64 KiB")
    return json.loads(raw), raw


def bind(evidence, records):
    """Requires the two fresh validated native PIDs to own the retained reads."""
    pids = {row["pid"] for row in records}
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise ValueError("expected two original fresh clock-read runs")
    if {run["pid"] for run in evidence} != pids:
        raise ValueError("clock-read and native ownership PIDs differ")
    for run in evidence:
        expected = [f"{batch}-{clock}" for batch in range(2)
                    for clock in ("realtime", "monotonic", "gettimeofday", "tsc")]
        if [read["instance"] for read in run["reads"]] != expected:
            raise ValueError("missing or reordered original read returns")
        if [boundary["sequence"] for boundary in run["boundaries"]] != [2, 3, 4]:
            raise ValueError("original selectable barrier chain is incomplete")
        holds = [row for row in records
                 if row["pid"] == run["pid"] and row["phase"] in ("before", "after")]
        if len(holds) != 2 or any((row["ps"], row["raw"]) !=
                                  (run["idle_ps"], run["idle_raw"]) for row in holds):
            raise ValueError("native hold does not bind the original host idle calibration")
        if run["wake_ps"] <= run["idle_ps"] or len(run["events"]) != 17:
            raise ValueError("original authenticated event or authorized wake evidence is incomplete")


def self_test():
    # Parser contracts only; these values never stand in for a physical read.
    expected = [f"{batch}-{clock}" for batch in range(2)
                for clock in ("realtime", "monotonic", "gettimeofday", "tsc")]
    evidence = [{"pid": pid, "reads": [{"instance": instance} for instance in expected],
                 "boundaries": [{"sequence": sequence} for sequence in (2, 3, 4)],
                 "idle_ps": 450, "idle_raw": 9, "wake_ps": 1000, "events": [None] * 17}
                for pid in (100, 200)]
    records = [{"pid": pid, "phase": phase, "raw": 9, "ps": 450}
               for pid in (100, 200) for phase in ("before", "after")]
    bind(evidence, records)
    changes = [
        lambda run: run.update(pid=300),
        lambda run: run["reads"].pop(),
        lambda run: run["reads"].reverse(),
        lambda run: run["boundaries"].pop(),
        lambda run: run.update(idle_raw=10),
        lambda run: run.update(wake_ps=450),
        lambda run: run["events"].pop(),
    ]
    for change in changes:
        altered = copy.deepcopy(evidence)
        change(altered[0])
        try:
            bind(altered, records)
        except ValueError:
            continue
        raise AssertionError("accepted invalid original clock/native binding")
    try:
        read_evidence(io.BytesIO(b" " * (MAX_EVIDENCE + 1)))
    except ValueError:
        pass
    else:
        raise AssertionError("accepted oversized evidence")
    print("PASS clock/native binding parser positive=1 negative=8 (schema fixtures only)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path, nargs="?")
    parser.add_argument("capture", type=Path, nargs="?")
    parser.add_argument("ownership_parser", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if any(path is None for path in (args.evidence, args.capture, args.ownership_parser)):
        parser.error("evidence, capture and ownership parser are required")

    specification = importlib.util.spec_from_file_location("time_ownership", args.ownership_parser)
    ownership = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(ownership)
    with args.capture.open("rb") as stream:
        records = ownership.receipts(stream)
    ownership.validate(records)
    with args.evidence.open("rb") as stream:
        evidence, raw = read_evidence(stream)
    bind(evidence, records)
    print("PASS fresh guest clock-read equivalence processes=2 reads=16 original-native-idle-waits=2")
    print("absolute Linux API calibration and fork-child ownership remain unqualified")
    print(raw.decode("utf-8"))


if __name__ == "__main__":
    main()

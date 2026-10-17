"""Binds bounded host clock-read evidence to genuine native ownership receipts."""

import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile

MAX_EVIDENCE = 64 * 1024
MAX_LAUNCH_SOURCE = 256 * 1024
PS_PER_SECOND = 1_000_000_000_000
READ_INSTANCES = [f"{batch}-{clock}" for batch in range(2)
                  for clock in ("realtime", "monotonic", "gettimeofday", "tsc")]


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


def declared_rtc_epoch(launch_source):
    """Reads the canonical production launch declaration, not a kernel origin."""
    with launch_source.open("rb") as stream:
        raw = stream.read(MAX_LAUNCH_SOURCE + 1)
    if len(raw) > MAX_LAUNCH_SOURCE:
        raise ValueError("launch source exceeds 256 KiB")
    declarations = [line for line in raw.decode("utf-8").splitlines()
                    if line.lstrip().startswith("const DEFAULT_RTC_EPOCH_UTC:")]
    if len(declarations) != 1:
        raise ValueError("expected one original RTC epoch declaration")
    match = re.fullmatch(
        r'const DEFAULT_RTC_EPOCH_UTC: &str = "([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})";',
        declarations[0],
    )
    if match is None:
        raise ValueError("original RTC epoch declaration is not canonical")
    epoch = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    elapsed = epoch - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return elapsed.days * 86_400 + elapsed.seconds


def affine_consistency(evidence, rtc_epoch_seconds):
    """Requires one offset at nominal rate one across the original API brackets."""
    if type(rtc_epoch_seconds) is not int:
        raise ValueError("source-declared RTC epoch must be integral seconds")
    lower = None
    upper = None
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise ValueError("expected two original fresh clock-read runs")
    for run in evidence:
        if [read["instance"] for read in run["reads"]] != READ_INSTANCES:
            raise ValueError("missing or reordered original read returns")
        for read in run["reads"]:
            clock = read["instance"].split("-", 1)[1]
            if clock == "tsc":
                continue
            quantum_ps = 1_000_000 if clock == "gettimeofday" else 1_000
            fraction_limit = 1_000_000 if clock == "gettimeofday" else 1_000_000_000
            unit = "microseconds" if clock == "gettimeofday" else "nanoseconds"
            before, after = read["before_ps"], read["after_ps"]
            seconds, fraction = read["seconds"], read["fraction"]
            if (any(type(value) is not int for value in (before, after, seconds, fraction))
                    or not 0 <= before < after <= 2**64 - 1
                    or not 0 <= seconds <= 2**63 - 1
                    or not 0 <= fraction < fraction_limit
                    or read["unit"] != unit):
                raise ValueError("affine check requires original normalized API brackets")

            # The RTC epoch relation is a source-declared hypothesis. The
            # common boot offset is bounded here, not authenticated or fitted.
            epoch_seconds = 0 if clock == "monotonic" else rtc_epoch_seconds
            returned_ps = (seconds - epoch_seconds) * PS_PER_SECOND + fraction * quantum_ps
            # The read happened somewhere inside its original bracket. Keep
            # the API's bucket width; neither endpoint is its exact timestamp.
            candidate_lower = returned_ps - after
            candidate_upper = returned_ps + quantum_ps - before
            lower = candidate_lower if lower is None else max(lower, candidate_lower)
            upper = candidate_upper if upper is None else min(upper, candidate_upper)
            if lower >= upper:
                raise ValueError("original Linux API brackets have no common offset at nominal rate one")
    return lower, upper


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
    affine_self_test()
    rtc_epoch_self_test()


def affine_self_test():
    # These hand-declared tuples are parser fixtures, not physical receipts.
    epoch = 1_000
    evidence = []
    for pid in (100, 200):
        reads = []
        for batch in range(2):
            tuples = [(epoch + batch, 1_010_050, "nanoseconds"),
                      (batch, 1_011_050, "nanoseconds"),
                      (epoch + batch, 1_012, "microseconds"),
                      (0, 0, "cycles")]
            for index, (seconds, fraction, unit) in enumerate(tuples):
                before = 1_000_000_000 + batch * PS_PER_SECOND + index * 1_000_000
                reads.append({"instance": READ_INSTANCES[batch * 4 + index],
                              "before_ps": before, "after_ps": before + 100_000,
                              "seconds": seconds, "fraction": fraction, "unit": unit})
        evidence.append({"pid": pid, "reads": reads})

    original_interval = affine_consistency(evidence, epoch)
    shifted = copy.deepcopy(evidence)
    for run in shifted:
        for read in run["reads"]:
            read["before_ps"] += 50_000_000
            read["after_ps"] += 50_000_000
    assert affine_consistency(shifted, epoch) == tuple(value - 50_000_000 for value in original_interval)

    def wrong_scale(run):
        for read in run["reads"]:
            read["before_ps"] *= 1_000
            read["after_ps"] *= 1_000

    def wrong_batch_rate(run):
        for read in run["reads"][4:7]:
            read["seconds"] += 1

    changes = [
        ("ps/ns scale", wrong_scale),
        ("second-batch rate", wrong_batch_rate),
        ("API epoch", lambda run: run["reads"][0].update(seconds=epoch + 1)),
        ("per-clock offset", lambda run: run["reads"][1].update(fraction=1_511_050)),
        ("half-open bucket", lambda run: run["reads"][1].update(fraction=1_011_151)),
        ("API unit", lambda run: run["reads"][0].update(unit="microseconds")),
        ("read bracket", lambda run: run["reads"][0].update(after_ps=1_000_000_000)),
        ("fraction bucket", lambda run: run["reads"][0].update(fraction=1_000_000_000)),
        ("integral coordinate", lambda run: run["reads"][0].update(before_ps=True)),
    ]
    for name, change in changes:
        altered = copy.deepcopy(evidence)
        change(altered[0])
        try:
            affine_consistency(altered, epoch)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid nominal-rate affine {name}")
    try:
        affine_consistency(evidence, epoch + 1)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted an inconsistent source-declared RTC epoch")
    print("PASS nominal-rate affine parser positive=2 negative=10 (schema fixtures only)")


def rtc_epoch_self_test():
    # Source-declaration fixtures authenticate syntax only, not a kernel epoch.
    canonical = b'const DEFAULT_RTC_EPOCH_UTC: &str = "2026-01-01T00:00:00";\n'
    with tempfile.TemporaryDirectory(prefix="clock-rtc-source-") as directory:
        path = Path(directory) / "launch.rs"
        path.write_bytes(canonical)
        assert declared_rtc_epoch(path) == 1_767_225_600
        cases = [
            ("missing", b""),
            ("duplicate", canonical * 2),
            ("indented duplicate", canonical + b"    " + canonical),
            ("noncanonical", canonical.replace(b"T00:00:00", b"T00:00:00Z")),
            ("invalid date", canonical.replace(b"01-01", b"02-30")),
            ("oversized", b" " * (MAX_LAUNCH_SOURCE + 1)),
        ]
        for name, data in cases:
            path.write_bytes(data)
            try:
                declared_rtc_epoch(path)
            except ValueError:
                continue
            raise AssertionError(f"accepted invalid RTC source declaration: {name}")
    print("PASS RTC source parser positive=1 negative=6 (schema fixtures only)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path, nargs="?")
    parser.add_argument("capture", type=Path, nargs="?")
    parser.add_argument("ownership_parser", type=Path, nargs="?")
    parser.add_argument("launch_source", type=Path, nargs="?")
    parser.add_argument("--runtime-anchor", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if any(path is None for path in (args.evidence, args.capture, args.ownership_parser, args.launch_source)):
        parser.error("evidence, capture, ownership parser and original launch source are required")

    specification = importlib.util.spec_from_file_location("time_ownership", args.ownership_parser)
    ownership = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(ownership)
    with args.capture.open("rb") as stream:
        records = ownership.receipts(stream)
    ownership.validate(records)
    with args.evidence.open("rb") as stream:
        evidence, raw = read_evidence(stream)
    bind(evidence, records)
    epoch = declared_rtc_epoch(args.launch_source)
    if args.runtime_anchor is None:
        lower, upper = affine_consistency(evidence, epoch)
    else:
        specification = importlib.util.spec_from_file_location("clock_vvar", args.runtime_anchor)
        runtime = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(runtime)
        runtime.validate(evidence)
    print("PASS fresh guest clock-read equivalence processes=2 reads=16 original-native-idle-waits=2")
    if args.runtime_anchor is None:
        print(f"PASS nominal-rate Linux API affine consistency source_rtc_epoch_seconds={epoch} offset_ps=[{lower},{upper})")
    else:
        print("PASS published-kernel runtime conversion consistency processes=2 reads=16")
    print("absolute Linux API calibration and fork-child ownership remain unqualified")
    print(raw.decode("utf-8"))


if __name__ == "__main__":
    main()

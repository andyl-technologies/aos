"""Validates bounded production-plugin time-owner and native-wait receipts."""

import argparse
import io
import re
from pathlib import Path

OWNER = b"CRUCIBLE-TIME-OWNER-V1 "
HOLD = b"CRUCIBLE-TIME-HOLD-V1 "
MAX_INPUT = 16 * 1024 * 1024
MAX_RECORD_BYTES = 256
MAX_RETAINED = 64 * 1024
FIELDS = {
    "acquired": {"phase", "pid", "raw", "ps", "owned"},
    "first-tb": {
        "phase",
        "pid",
        "vcpu",
        "tb",
        "entry_status",
        "entry_raw",
        "charged_raw",
        "charged_ps",
        "owned",
    },
    "idle-before": {"phase", "pid", "vcpu", "wait", "raw", "ps"},
    "idle-after": {"phase", "pid", "vcpu", "wait", "status", "raw", "ps"},
    "before": {"phase", "pid", "raw", "ps"},
    "after": {"phase", "pid", "raw", "ps"},
}


def receipts(stream):
    """Streams a finite input while retaining first ownership rows separately."""
    records = []
    read_bytes = 0
    retained_bytes = 0
    while line := stream.readline(MAX_INPUT + 1):
        read_bytes += len(line)
        if read_bytes > MAX_INPUT:
            raise ValueError("diagnostic input exceeds 16 MiB")
        prefix = next((prefix for prefix in (OWNER, HOLD) if line.startswith(prefix)), None)
        if prefix is None:
            continue
        retained_bytes += len(line)
        if len(line) > MAX_RECORD_BYTES or retained_bytes > MAX_RETAINED:
            raise ValueError("time-owner receipt bound exceeded")
        fields = {}
        for item in line[len(prefix):].decode("ascii").strip().split(" "):
            key, value = item.split("=")
            if key in fields:
                raise ValueError("duplicate receipt field")
            fields[key] = value
        phase = fields.get("phase")
        if phase not in FIELDS or set(fields) != FIELDS[phase]:
            raise ValueError("unexpected time-owner schema")
        if (prefix == HOLD) != (phase in {"before", "after"}):
            raise ValueError("wrong receipt prefix")
        for key, value in tuple(fields.items()):
            if key == "phase":
                continue
            if not re.fullmatch(r"0|[1-9][0-9]*|-([1-9][0-9]*)", value):
                raise ValueError("noncanonical scalar")
            scalar = int(value)
            if key in {"ps", "charged_ps"}:
                valid = 0 <= scalar <= 2**63 - 1
            elif key in {"status", "entry_status"}:
                valid = -(2**31) <= scalar <= 2**31 - 1
            elif key in {"pid", "vcpu"}:
                valid = 0 <= scalar <= 2**32 - 1 and (key != "pid" or scalar != 0)
            elif key == "owned":
                valid = scalar in (0, 1)
            else:
                valid = 0 <= scalar <= 2**64 - 1
            if not valid:
                raise ValueError("out-of-range scalar")
            fields[key] = scalar
        records.append(fields)
    return records


def validate(records):
    pids = {row["pid"] for row in records if row["phase"] == "before"}
    if len(pids) != 2 or {row["pid"] for row in records} != pids:
        raise ValueError("expected exactly two owned production flight processes")
    for pid in pids:
        rows = [(index, row) for index, row in enumerate(records) if row["pid"] == pid]
        phases = {phase: [(index, row) for index, row in rows if row["phase"] == phase]
                  for phase in FIELDS}
        if any(len(phases[phase]) != 1 for phase in ("acquired", "first-tb", "before", "after")):
            raise ValueError("missing or repeated ownership/hold evidence")
        acquired_index, acquired = phases["acquired"][0]
        first_index, first = phases["first-tb"][0]
        before_index, before = phases["before"][0]
        after_index, after = phases["after"][0]
        if not acquired_index < first_index < before_index < after_index:
            raise ValueError("ownership/first execution/hold ordering changed")
        if acquired["owned"] != 1 or first["owned"] != 1 or first["entry_status"] != 0:
            raise ValueError("original time ownership or exact entry observation refused")
        # The install-time fixed epoch precedes guest execution; the first TB
        # observation has already debited that TB. Do not assert charged raw0.
        if acquired["raw"] != 0 or acquired["ps"] != 0 or first["entry_raw"] != acquired["raw"]:
            raise ValueError("guest execution or clock movement preceded ownership")
        if first["tb"] == 0 or first["charged_raw"] != first["entry_raw"] + first["tb"]:
            raise ValueError("TB charge/entry relation is incoherent")
        if first["charged_ps"] != acquired["ps"] + first["tb"] * 50:
            raise ValueError("first execution did not retain the original fixed epoch")
        if (before["raw"], before["ps"]) != (after["raw"], after["ps"]):
            raise ValueError("clock moved during withheld scheduler grant")
        if len(phases["idle-before"]) > 60 or len(phases["idle-after"]) > 60:
            raise ValueError("native waiter receipt count exceeded")
        matched = False
        seen = set()
        for begin_index, begin in phases["idle-before"]:
            key = (begin["vcpu"], begin["wait"])
            if key in seen or begin["wait"] >= 60:
                raise ValueError("duplicate or out-of-range native waiter")
            seen.add(key)
            ends = [(index, row) for index, row in phases["idle-after"]
                    if (row["vcpu"], row["wait"]) == key]
            if len(ends) != 1 or ends[0][0] <= begin_index:
                raise ValueError("native wait pair is incomplete or reversed")
            end_index, end = ends[0]
            if begin_index < before_index < after_index < end_index and end["status"] in (0, 1, 2):
                coordinates = {(row["raw"], row["ps"]) for row in (begin, end, before, after)}
                matched |= len(coordinates) == 1
        if len(phases["idle-after"]) != len(seen) or not matched:
            raise ValueError("no admitted RUNNING native waiter spans the unchanged idle hold")
    return len(pids)


def self_test():
    # These are parser fixtures only, never claimed as execution receipts.
    def case(pid):
        return (f"CRUCIBLE-TIME-OWNER-V1 phase=acquired pid={pid} raw=0 ps=0 owned=1\n"
                f"CRUCIBLE-TIME-OWNER-V1 phase=first-tb pid={pid} vcpu=0 tb=3 entry_status=0 entry_raw=0 charged_raw=3 charged_ps=150 owned=1\n"
                f"CRUCIBLE-TIME-OWNER-V1 phase=idle-before pid={pid} vcpu=0 wait=0 raw=9 ps=450\n"
                f"CRUCIBLE-TIME-HOLD-V1 phase=before pid={pid} raw=9 ps=450\n"
                f"CRUCIBLE-TIME-HOLD-V1 phase=after pid={pid} raw=9 ps=450\n"
                f"CRUCIBLE-TIME-OWNER-V1 phase=idle-after pid={pid} vcpu=0 wait=0 status=0 raw=9 ps=450\n")
    original = (case(100) + case(200)).encode()
    assert validate(receipts(io.BytesIO(original))) == 2
    changes = [
        (b"owned=1", b"owned=0"),
        (b"entry_status=0", b"entry_status=-1"),
        (b"charged_raw=3", b"charged_raw=0"),
        (b"charged_ps=150", b"charged_ps=149"),
        (b"status=0 raw=9", b"status=10 raw=9"),
        (b"wait=0", b"wait=60"),
        (b"phase=after pid=100 raw=9", b"phase=after pid=100 raw=10"),
        (b"pid=100", b"pid=0100"),
        (b"entry_raw=0", b"entry_raw=18446744073709551616"),
    ]
    for old, new in changes:
        try:
            validate(receipts(io.BytesIO(original.replace(old, new))))
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid receipt {new!r}")
    lines = original.splitlines(keepends=True)
    invalid_orderings = [
        lines[:2] + lines[3:],  # missing native wait entry
        lines[:-1],  # missing native wait return
        lines[:3] + [lines[2]] + lines[3:],  # repeated native wait entry
        lines[:6] + [lines[5]] + lines[6:],  # repeated native wait return
        lines[:2] + [lines[5]] + lines[3:5] + [lines[2]] + lines[6:],
        [lines[1], lines[0]] + lines[2:],  # first execution precedes ownership
        lines[:3] + [lines[4], lines[3]] + lines[5:],  # reversed host hold
        lines[:1] + lines[2:],  # missing first execution evidence
    ]
    for reordered in invalid_orderings:
        try:
            validate(receipts(io.BytesIO(b"".join(reordered))))
        except ValueError:
            continue
        raise AssertionError("accepted missing, repeated, or reordered evidence")
    for data in (b"x" * (MAX_INPUT + 1), OWNER + b"x" * MAX_RECORD_BYTES):
        try:
            receipts(io.BytesIO(data))
        except ValueError:
            continue
        raise AssertionError("accepted oversized diagnostic capture")
    print("PASS parser positive=1 negative=19 (schema fixtures only)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        with args.capture.open("rb") as stream:
            count = validate(receipts(stream))
        print(f"PASS production time ownership processes={count} native-running-idle-waits=2")


if __name__ == "__main__":
    main()

"""Checks the fixed one-CPU deployed oracle log contract.

Text validation is not physical authentication. The enclosing gate must bind
its actual artifact pair, original admission, guest workload and executed log.
"""

import argparse
import re
from pathlib import Path

FIRST = 700_000
SECOND = 1_400_000
MAX_RECORD = 1024
NATIVE_PREFIX = "crucible RAM owner diagnostic "
HOST_PREFIX = "complete_write_oracle_"
OWNER = re.compile(
    r"crucible RAM owner diagnostic raw=(\d+) vmstop=(\d+) topology=(\d+) "
    r"token=(\d+) first=(-?\d+) proc_close=(-?\d+) release=(-?\d+) "
    r"capture_generation=(\d+) capture=(-?\d+) attempted=(\d+)"
)
BASELINE = re.compile(r"complete_write_oracle_baseline raw=1 hash=[0-9a-f]{64}")
FIRST_ROOT = re.compile(r"complete_write_oracle_first raw=700000 hash=[0-9a-f]{64}")
WRITE = re.compile(r"complete_write_oracle_write raw=1400000 before=([0-9a-f]{16}) after=([0-9a-f]{16})")


def records(stream):
    while first := stream.readline(MAX_RECORD + 1):
        candidate = first.startswith((NATIVE_PREFIX.encode(), HOST_PREFIX.encode()))
        if len(first) > MAX_RECORD:
            if candidate:
                raise ValueError("oversized oracle record")
            while not first.endswith(b"\n"):
                first = stream.readline(MAX_RECORD + 1)
                if not first:
                    break
            continue
        if candidate:
            yield first.rstrip(b"\n").decode("ascii")


def validate(lines, role):
    if role not in ["oracle-positive", "notification-adversary"]:
        raise ValueError("explicit fixed artifact role required")
    negative = role == "notification-adversary"
    phase = 0
    owners = []
    for line in lines:
        if len(line) > MAX_RECORD:
            raise ValueError("oversized oracle record")
        if not line.startswith((NATIVE_PREFIX, HOST_PREFIX)):
            continue
        owner = OWNER.fullmatch(line)
        if owner:
            if phase not in [1, 3]:
                raise ValueError("oracle ran without prior baseline or after identity repair")
            fields = tuple(map(int, owner.groups()))
            if any(str(value) != encoded for value, encoded in zip(fields, owner.groups())):
                raise ValueError("noncanonical owner scalar")
            for index, value in enumerate(fields):
                lower, upper = (-(1 << 31), 1 << 31) if index in [4, 5, 6, 8] else (0, 1 << (32 if index == 9 else 64))
                if not lower <= value < upper:
                    raise ValueError("owner scalar exceeds native field width")
            raw, vmstop, topology, token, first, proc_close, release, generation, capture, attempted = fields
            expected_raw = FIRST if phase == 1 else SECOND
            expected_status = -74 if negative and phase == 3 else 0
            if raw != expected_raw or first != expected_status:
                raise ValueError("not the reached fixed comparison outcome")
            if not all(value > 0 for value in [vmstop, topology, token, generation]):
                raise ValueError("missing genuine owner/capture coordinates")
            if (proc_close, release, capture, attempted) != (0, 0, 0, 1):
                raise ValueError("uncertain owner/capture cleanup")
            if owners and (topology != owners[0][2] or token == owners[0][3] or vmstop <= owners[0][1]):
                raise ValueError("topology drift or reused stopped physical owner")
            owners.append(fields)
            phase += 1
        elif phase == 0 and BASELINE.fullmatch(line):
            phase = 1
        elif phase == 2 and FIRST_ROOT.fullmatch(line):
            phase = 3
        elif phase == 4 and (write := WRITE.fullmatch(line)):
            if write[1] == write[2]:
                raise ValueError("no independently observed guest RAM write")
            phase = 5
        elif phase == 5 and line == "complete_write_oracle_identity " + ("unavailable=true" if negative else "changed=true"):
            phase = 6
        elif phase == 6 and line == "complete_write_oracle_cleanup reaped=true resources_restored=true":
            phase = 7
        else:
            raise ValueError("unexpected, duplicated, stale or out-of-order oracle record")
    if phase != 7 or len(owners) != 2:
        raise ValueError("incomplete genuine baseline/write/comparison/cleanup evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--role", choices=["oracle-positive", "notification-adversary"], required=True)
    args = parser.parse_args()
    with args.log.open("rb") as stream:
        validate(records(stream), args.role)
    print("COMPLETE_WRITE_ORACLE_ONE_CPU_LOG_CONTRACT_PASS")


if __name__ == "__main__":
    main()

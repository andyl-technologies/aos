# SPDX-License-Identifier: Apache-2.0
"""Selects conservative local Bazel admission for Envoy's C++ compilation."""

import argparse
import json
import os
from pathlib import Path
import sys

GIB = 1024**3
COMPILER_BYTES = 3 * GIB
MAX_RESERVE_BYTES = 32 * GIB


def admission(cores, limit, current, maximum=None):
    """Leaves service headroom and reserves three GiB per local action."""
    reserve = min(MAX_RESERVE_BYTES, max(GIB, limit // 8))
    available = max(0, limit - current - reserve)
    actions = min(cores, available // COMPILER_BYTES)
    return min(actions, maximum) if maximum is not None else actions


def physical_memory():
    """Reads Linux's physical and currently available memory in bytes."""
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in ("MemTotal", "MemAvailable"):
            fields[name] = int(value.split()[0]) * 1024
    return fields["MemTotal"], fields["MemAvailable"]


def discover_cgroup():
    """Returns a visible unified cgroup directory, if the sandbox exposes it."""
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            directory = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
            if (directory / "memory.current").is_file():
                return directory
    return None


def budget(directory):
    """Reads explicit service limits or uses conservative physical headroom."""
    total, available = physical_memory()
    if directory is None:
        return total, total - available, "physical-memory-fallback"

    limits = [total]
    for name in ("memory.high", "memory.max"):
        value = (directory / name).read_text().strip()
        if value != "max":
            limits.append(int(value))
    current = int((directory / "memory.current").read_text().strip())
    return min(limits), current, "cgroup-v2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cores", type=int, required=True)
    parser.add_argument("--cgroup-dir", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--max-actions", type=int)
    args = parser.parse_args()
    cores = args.cores or os.cpu_count() or 1
    if cores < 1:
        parser.error("cores must be positive or zero for automatic detection")

    if args.max_actions is not None and args.max_actions < 1:
        parser.error("max-actions must be positive")

    directory = args.cgroup_dir or discover_cgroup()
    limit, current, source = budget(directory)
    actions = admission(cores, limit, current, args.max_actions)
    facts = {
        "source": source,
        "limit_bytes": limit,
        "current_bytes": current,
        "reserve_bytes": min(MAX_RESERVE_BYTES, max(GIB, limit // 8)),
        "compiler_bytes": COMPILER_BYTES,
        "requested_cores": cores,
        "maximum_actions": args.max_actions,
        "local_cpu_admission": actions,
    }
    if args.probe:
        print(json.dumps(facts, sort_keys=True))
        return

    print("envoy-build-resources " + json.dumps(facts, sort_keys=True), file=sys.stderr)
    if actions < 1:
        raise SystemExit("insufficient memory headroom for one Envoy compiler action")
    print(f"build --local_resources=cpu={actions}")


if __name__ == "__main__":
    main()

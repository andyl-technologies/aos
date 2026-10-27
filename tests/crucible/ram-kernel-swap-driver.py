# SPDX-License-Identifier: Apache-2.0
"""Bind the fixed research requests before the original native owner launches.

This command prepares immutable inputs and checks recorded dispositions. It
does not launch, authorize a native role, install swap, or certify retirement.
The actual consuming original owner is a separate required runtime dependency.
Resident qualification is separately counted; its rows use the same seeds and
work as the 81-row research matrix rather than reusing different seed families.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


spec = importlib.util.spec_from_file_location(
    "completed_work", Path(__file__).with_name("ram-completed-throughput-compare.py")
)
completed_work = importlib.util.module_from_spec(spec)
spec.loader.exec_module(completed_work)

DELAYS_MS = (0, 10, 100)
GUEST_BYTES = 512 << 20
MATERIALIZED_BYTES = 384 << 20
SWAP_BYTES = 4 << 30
MAX_RECLAIM_ROUNDS = 4
SCHEMA = "crucible.kernel-swap-fixed-input.v1"
ARTIFACT_ROLES = ("kernel", "initrd", "root", "workload", "qemu", "plugin", "qemu_source", "driver")
MAX_RECEIPT_BYTES = 8 << 20


def requests(variant):
    """Return the exact 81 rows and 189 separately identified attempt inputs."""
    completed_work.require(variant in ("kernel-swap", "resident-baseline"), "variant")
    rows = []
    for delay in DELAYS_MS:
        for target in completed_work.TARGETS:
            for parallel in completed_work.PARALLEL:
                for repeat in completed_work.REPEATS:
                    seeds = sorted(completed_work.expected_seeds(target, parallel, repeat))
                    rows.append({
                        "delay_ms": delay, "target_divisor": target,
                        "parallel": parallel, "repeat": repeat,
                        "attempts": [{
                            "id": f"d{delay}-t{target}-p{parallel}-r{repeat}-w{worker}",
                            "seed": seed,
                            "target_bytes": (GUEST_BYTES if variant == "resident-baseline"
                                             else GUEST_BYTES // target if target else 0),
                        } for worker, seed in enumerate(seeds)],
                    })
    return rows


def pin_artifact(path):
    """Stream actual bytes without materializing guest images in driver memory."""
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        completed_work.require(stat.S_ISREG(before.st_mode), "artifact is not a regular file")
        count = 0
        while block := source.read(65536):
            count += len(block)
            completed_work.integer(count, "artifact length", 1)
            digest.update(block)
        after = os.fstat(source.fileno())
        named = path.lstat()
    completed_work.require(count > 0, "empty artifact")
    completed_work.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                           == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                           and (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino)
                           and count == before.st_size, "artifact changed during pinning")
    return {"sha256": digest.hexdigest(), "bytes": count}


def prepare(variant, artifacts):
    completed_work.require(set(artifacts) == set(ARTIFACT_ROLES), "artifact roles")
    rows = requests(variant)
    return {
        "schema": SCHEMA, "variant": variant,
        "guest_bytes": GUEST_BYTES, "materialized_bytes": MATERIALIZED_BYTES,
        "workload_seed": 42, "quanta_per_attempt": 32, "maximum_quanta": 50000,
        "swap_partition_bytes": SWAP_BYTES, "maximum_reclaim_rounds": MAX_RECLAIM_ROUNDS,
        "swappiness": 200, "attempt_seconds": 1200,
        "matrix_seconds": 3600, "outer_seconds": 3900,
        "assignment_resources": dict(zip(completed_work.RESOURCE_FIELDS,
                                         (1536 << 20, 4 << 30, 512 << 20, 32 << 20,
                                          1, 1, 69, 1056))),
        "rows": rows, "attempt_count": sum(len(row["attempts"]) for row in rows),
        "separate_resident_baseline": variant == "resident-baseline",
        "artifacts": {role: pin_artifact(artifacts[role]) for role in ARTIFACT_ROLES},
        "launch_eligible": False,
        "holds": ["genuine native/domain/Source/swap role and concrete factory are not supplied by this input file",
                  "whole runtime original owner must include dispatch/preparation through physical cleanup",
                  "actual cross-edition common complete-state/RAM witness remains required"],
    }


def target_disposition(request, observation):
    """Keep interval evidence truthful rather than certify simultaneous targets."""
    for field in ("pte_present_pages", "pte_swapped_pages", "pte_absent_pages",
                  "resident_pages", "scan_zero_pages",
                  "sampled_swapped_nonresident_pages", "changed_pte_pages"):
        completed_work.integer(observation[field], f"counter {field}")
        completed_work.require(observation[field] <= GUEST_BYTES // 4096, "counter extent")
    completed_work.require(sum(observation[field] for field in
                               ("pte_present_pages", "pte_swapped_pages", "pte_absent_pages"))
                           == GUEST_BYTES // 4096, "incomplete page inventory")
    completed_work.require(observation["sampled_swapped_nonresident_pages"]
                           <= observation["pte_swapped_pages"], "unattributed swap sample")
    completed_work.require(request["target_bytes"] in (0, GUEST_BYTES // 2, GUEST_BYTES),
                           "changed target")
    # A zero swap sample cannot become evidence that a zero target was reached.
    if request["target_bytes"] == 0 and observation["pte_swapped_pages"] == 0:
        return "TargetNotReached"
    return "IntervalOnly"


def read_pinned(path, expected):
    completed_work.require(path.stat().st_size <= MAX_RECEIPT_BYTES, "oversized receipt")
    return completed_work.read_pinned(path, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("kernel-swap", "resident-baseline"), required=True)
    for role in ARTIFACT_ROLES:
        parser.add_argument(f"--{role.replace('_', '-')}", dest=role, type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = prepare(arguments.variant, {role: getattr(arguments, role) for role in ARTIFACT_ROLES})
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"kernel-swap input: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

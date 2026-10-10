"""Collect paired resident timing and Linux scheduling diagnostics.

Each variant runs its own snapshotted boundary driver and plugin protocol. The
only instrumentation replaces that driver's two CPU-accounting reads with a
read of the same accounting plus per-thread schedstat. Guest commands, timing
boundaries, restore and independent architectural oracles remain unchanged.
This diagnostic dataset has no acceptance margin or performance pass verdict.
Run with AOS-built Python, QEMU packages and their matching fixture packages.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import time


def file_identity(path):
    """Identify the exact bytes consumed by a measurement."""
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def kernel_identity():
    """Record native uname fields without depending on a namedtuple layout."""
    identity = os.uname()
    return {field: getattr(identity, field)
            for field in ("sysname", "nodename", "release", "version", "machine")}


def process_stat(path):
    """Parse stat after its potentially space-containing process name."""
    text = path.read_text()
    fields = text.rsplit(")", 1)[1].split()
    return {
        "raw": text,
        "user_ticks": int(fields[11]),
        "system_ticks": int(fields[12]),
        "start_ticks": int(fields[19]),
    }


def scheduler_snapshot(pid):
    """Retain raw process and thread counters without guessing missing values."""
    started = time.monotonic_ns()
    root = Path(f"/proc/{pid}")
    process = process_stat(root / "stat")
    threads = {}
    missing = []
    for task in sorted((root / "task").iterdir(), key=lambda path: int(path.name)):
        try:
            stat = process_stat(task / "stat")
            raw = (task / "schedstat").read_text()
            values = [int(value) for value in raw.split()]
            if len(values) != 3:
                raise ValueError(f"unexpected schedstat fields for {task}: {raw!r}")
            # Linux exposes on-CPU nanoseconds, runqueue wait nanoseconds and
            # timeslices. These are distinct from process CPU clock ticks.
            threads[task.name] = dict(
                stat, schedstat_raw=raw, runtime_ns=values[0],
                runqueue_wait_ns=values[1], timeslices=values[2],
            )
        except FileNotFoundError:
            missing.append(task.name)
    return {
        "pid": pid, "process": process, "threads": threads,
        "missing_during_read": missing, "started_monotonic_ns": started,
        "finished_monotonic_ns": time.monotonic_ns(),
    }


def scheduling_delta(before, after, counters_available=True):
    """Report stable-thread deltas and explicitly identify incomplete coverage."""
    if (before["pid"] != after["pid"] or
            before["process"]["start_ticks"] != after["process"]["start_ticks"]):
        raise ValueError("process identity changed across the measured boundary")
    old, new = before["threads"], after["threads"]
    born = sorted(set(new) - set(old))
    departed = sorted(set(old) - set(new))
    reused, regressed = [], []
    deltas = {}
    fields = ("runtime_ns", "runqueue_wait_ns", "timeslices")
    for tid in sorted(set(old) & set(new)):
        if old[tid]["start_ticks"] != new[tid]["start_ticks"]:
            reused.append(tid)
            continue
        delta = {field: new[tid][field] - old[tid][field] for field in fields}
        if any(value < 0 for value in delta.values()):
            regressed.append(tid)
            continue
        deltas[tid] = delta
    return {
        "scheduling_counters_available": counters_available,
        "complete_thread_coverage": not (
            born or departed or reused or regressed or
            before["missing_during_read"] or after["missing_during_read"]
        ),
        "born_threads": born, "departed_threads": departed,
        "reused_threads": reused, "regressed_threads": regressed,
        "stable_thread_deltas": deltas if counters_available else None,
        "stable_thread_totals": {
            field: sum(delta[field] for delta in deltas.values()) for field in fields
        } if counters_available else None,
        "process_tick_delta": {
            field: after["process"][field] - before["process"][field]
            for field in ("user_ticks", "system_ticks")
        },
    }


def observed_boundary(driver, *args, scheduling_available=True, **kwargs):
    """Instrument the original driver's existing two CPU observation sites."""
    boundary = driver["run_boundary"]
    namespace = boundary.__globals__
    original = namespace["cpu_seconds"]
    snapshots = []

    def observed_cpu_seconds(pid):
        snapshot = scheduler_snapshot(pid)
        snapshots.append(snapshot)
        ticks = os.sysconf("SC_CLK_TCK")
        stat = snapshot["process"]
        return stat["user_ticks"] / ticks, stat["system_ticks"] / ticks

    namespace["cpu_seconds"] = observed_cpu_seconds
    try:
        sample = boundary(*args, **kwargs)
    except BaseException as error:
        # Preserve partial diagnostic reads on failure, without treating an
        # incomplete run as a valid timing or synthesizing missing counters.
        error.scheduling_observations = snapshots
        raise
    finally:
        namespace["cpu_seconds"] = original
    if len(snapshots) != 2:
        raise ValueError(f"expected two original CPU observations, got {len(snapshots)}")
    sample["scheduling"] = {
        "before": snapshots[0], "after": snapshots[1],
        "delta": scheduling_delta(*snapshots, counters_available=scheduling_available),
    }
    return sample


def append_record(output, row):
    """Persist every successful boundary, including checkpoint producers."""
    with (output / "samples.jsonl").open("a") as stream:
        stream.write(json.dumps(row) + "\n")
        stream.flush()
    print(json.dumps({key: row[key] for key in
                      ("variant", "trial", "mode", "workload", "seconds")}), flush=True)


def bind_predeclared_plan(metadata, path):
    """Match exact artifact and sampling identities before any guest launches."""
    plan = json.loads(path.read_text())
    if (plan["schema"] != "crucible.resident.confirmation-plan.v1" or
            plan["status"] != "bound"):
        raise ValueError("final performance plan is not bound to its package")
    bound = datetime.datetime.fromisoformat(plan["bound_utc"])
    started = datetime.datetime.fromisoformat(metadata["started_utc"])
    if bound.tzinfo is None or started.tzinfo is None or bound > started:
        raise ValueError("performance plan was not bound before this measurement")
    for field in ("sampling_plan", "cpu", "stop", "checkpoint",
                  "timeout_seconds", "clock_ticks_per_second",
                  "scheduling_counters_available", "kernel"):
        if metadata[field] != plan[field]:
            raise ValueError(f"measured {field} differs from predeclared plan")
    if metadata["driver"]["sha256"] != plan["measurement_driver_sha256"]:
        raise ValueError("measurement instrumentation differs from predeclared plan")
    for variant in ("baseline", "current"):
        for field in ("source_driver", "qemu", "plugin", "roms", "identity",
                      "normalized_guest_commands"):
            if metadata["artifacts"][variant][field] != plan["artifacts"][variant][field]:
                raise ValueError(f"{variant} {field} differs from predeclared plan")
    metadata["predeclared_plan"] = file_identity(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for variant in ("baseline", "current"):
        parser.add_argument(f"--{variant}-source", type=Path, required=True)
        parser.add_argument(f"--{variant}-qemu", type=Path, required=True)
        parser.add_argument(f"--{variant}-fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--pairs", type=int, default=40)
    parser.add_argument("--stop", type=int, default=240_000_000)
    parser.add_argument("--checkpoint", type=int, default=120_000_000)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--plan", type=Path,
                        help="Match a bound predeclared confirmation plan before guest launch")
    parser.add_argument("--require-scheduling-counters", action="store_true",
                        help="Refuse before launch if kernel runqueue accounting is disabled")
    args = parser.parse_args()
    if args.pairs < 2 or not 6 < args.checkpoint < args.stop:
        parser.error("require at least two pairs and 6 < checkpoint < stop")
    allowed = sorted(os.sched_getaffinity(0))
    if args.cpu not in allowed:
        parser.error("requested CPU is outside current affinity")
    schedstats = Path("/proc/sys/kernel/sched_schedstats").read_text().strip()
    scheduling_available = schedstats == "1"
    if args.require_scheduling_counters and not scheduling_available:
        parser.error("kernel.sched_schedstats must be enabled before the predeclared run; disabled runqueue accounting cannot diagnose scheduling delay")
    args.output.mkdir(parents=True, exist_ok=False)
    os.sched_setaffinity(0, {args.cpu})

    metadata = {
        "schema": "crucible.paired-resident-scheduling.v1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sampling_plan": {
            "pairs_per_workload_mode": args.pairs,
            "workloads": ["bios.bin", "io-bios.bin"],
            "modes": ["cold", "restored"],
            "order": "baseline/current on even trials, current/baseline on odd trials",
            "retention": "all samples and checkpoint producers; no optional stopping or exclusions",
        },
        "stop": args.stop, "checkpoint": args.checkpoint, "timeout_seconds": args.timeout,
        "cpu": args.cpu, "available_affinity": allowed,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "kernel": kernel_identity(),
        "sched_schedstats": schedstats,
        "scheduling_counters_available": scheduling_available,
        "scheduling_interpretation": (
            "Full thread scheduling counters are available."
            if scheduling_available else
            "Runqueue accounting is disabled. Raw schedstat values are retained but not interpreted; process CPU ticks and wall time remain available."
        ),
        "cpuinfo": Path("/proc/cpuinfo").read_text(),
        "driver": file_identity(Path(__file__).resolve()),
        "scope": "Component resident plugin; original QMP cont to exact stop ROI. Existing witnesses are full register text, retired count/tick, 256-byte physical RAM window SHA256 and independent first-eight-byte arithmetic. Scheduling snapshots straddle the ROI with separately recorded collection times.",
        "interpretation": "Diagnostic counters only; no managed workload or no-regression acceptance claim.",
        "artifacts": {},
    }
    variants = {}
    expected_commands = None
    for label in ("baseline", "current"):
        source = getattr(args, f"{label}_source") / "tests/crucible/tcg-performance.py"
        package = getattr(args, f"{label}_qemu")
        fixtures = getattr(args, f"{label}_fixtures")
        snapshot = args.output / f"{label}-boundary-driver.py"
        snapshot.write_bytes(source.read_bytes())
        driver = runpy.run_path(str(snapshot))
        variants[label] = (driver, package, fixtures)
        commands = {
            mode: driver["command"](
                Path("/qemu"), Path("/fixtures"), Path("/control"),
                args.stop, mode == "restored", Path("/bios"),
            ) for mode in ("cold", "restored")
        }
        if expected_commands is None:
            expected_commands = commands
        elif commands != expected_commands:
            raise AssertionError("paired original drivers use different guest configurations")
        metadata["artifacts"][label] = {
            "source_driver": file_identity(source), "snapshot": file_identity(snapshot),
            "qemu": file_identity(package / "bin/qemu-system-x86_64"),
            "plugin": file_identity(fixtures / "plugin.so"),
            "identity": (package / "share/aos/crucible/qemu-build-identity.env").read_text(),
            "roms": {name: file_identity(fixtures / name)
                     for name in ("bios.bin", "io-bios.bin")},
            "normalized_guest_commands": commands,
        }
    if args.plan is not None:
        bind_predeclared_plan(metadata, args.plan)
    manifest = args.output / "evidence.json"
    manifest.write_text(json.dumps(metadata, indent=2) + "\n")

    try:
        for workload, loop in (("bios.bin", 7), ("io-bios.bin", 8)):
            roms = [fixtures.joinpath(workload).read_bytes()
                    for _, _, fixtures in variants.values()]
            if roms[0] != roms[1]:
                raise AssertionError("paired workload ROM bytes differ")
            expected = None
            for trial in range(args.pairs):
                labels = ("baseline", "current") if trial % 2 == 0 else ("current", "baseline")
                for label in labels:
                    driver, package, fixtures = variants[label]
                    # Prime the independent arithmetic calculation outside all ROIs.
                    driver["reference_state"](args.stop, loop)
                    driver["reference_state"](args.checkpoint, loop)
                    with tempfile.TemporaryDirectory(prefix="crucible-resident-profile-") as temporary:
                        directory = Path(temporary)
                        vmstate = directory / "source.vmstate"
                        for mode, stop, extra in (
                            ("cold", args.stop, {}),
                            ("source", args.checkpoint, {"save": vmstate}),
                            ("restored", args.stop, {"restore": vmstate}),
                        ):
                            sample = observed_boundary(
                                driver, package / "bin/qemu-system-x86_64", fixtures,
                                stop, directory, mode, args.timeout,
                                bios=fixtures / workload,
                                scheduling_available=scheduling_available, **extra,
                            )
                            row = dict(sample, variant=label, trial=trial, mode=mode, workload=workload)
                            append_record(args.output, row)
                            driver["require_reference"](sample, stop, loop)
                            if mode != "source":
                                if expected is None:
                                    expected = sample["witness"]
                                if sample["witness"] != expected:
                                    raise AssertionError("paired architectural/RAM witness differs")
        metadata["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    except BaseException as error:
        metadata["failure"] = {"type": type(error).__name__, "message": str(error)}
        if hasattr(error, "scheduling_observations"):
            metadata["failure"]["scheduling_observations"] = error.scheduling_observations
        raise
    finally:
        manifest.write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()

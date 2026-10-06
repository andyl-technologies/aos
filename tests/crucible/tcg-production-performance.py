"""Interleave matched production-plugin/QEMU pairs at exact shared-memory grants.

Build the public-protocol host driver with tcg-production-performance-driver.nix.
Build each real plugin with the same release profile and that QEMU package's
CRUCIBLE_QEMU_BUILD_ID, CRUCIBLE_QEMU_ATOMIC_PATCH_HASH and
CRUCIBLE_SHMEM_HEADER_HASH. The package identity marker supplies these values.
Pass the resulting binaries with matching --qemu LABEL=PATH and --plugin
LABEL=PATH arguments. All execution and evidence collection occur locally.

The measured interval starts immediately before QMP cont and ends when the
public slot publishes the granted logical tick. Handshake, mapping allocation,
QMP setup, stop, and state capture are outside that interval. The production
plugin's coverage, fingerprint and whitebox observations are disabled.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import statistics
import subprocess

oracle = runpy.run_path(str(Path(__file__).with_name("tcg-performance.py")))
reference_state = oracle["reference_state"]
require_reference = oracle["require_reference"]


def labeled_paths(arguments):
    """Resolve explicitly paired local artifact labels."""
    result = {}
    for argument in arguments:
        label, path = argument.split("=", 1)
        if label in result:
            raise ValueError(f"duplicate artifact label {label}")
        result[label] = Path(path).resolve(strict=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--qemu", action="append", required=True)
    parser.add_argument("--plugin", action="append", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--host-cpu", type=int)
    parser.add_argument("--ram-horizon", type=int, default=500_000_000)
    parser.add_argument("--io-horizon", type=int, default=50_000_000)
    args = parser.parse_args()
    qemu = labeled_paths(args.qemu)
    plugins = labeled_paths(args.plugin)
    if len(qemu) != 2 or qemu.keys() != plugins.keys():
        raise ValueError("provide exactly two QEMU labels with matching plugin labels")
    if args.repetitions < 2 or min(args.ram_horizon, args.io_horizon) < 6:
        raise ValueError("use at least two repetitions and horizons after BIOS setup")
    if args.host_cpu is not None:
        os.sched_setaffinity(0, {args.host_cpu})
    args.output.mkdir(parents=True, exist_ok=True)
    results = {
        "scope": "Real production plugin; one public shared-memory grant; cold BIOS arithmetic/RAM and arithmetic/RAM/POST-port workloads; observations disabled.",
        "cpu": args.cpu,
        "host_cpu": args.host_cpu,
        "repetitions": args.repetitions,
        "artifacts": {
            label: {
                "qemu": str(binary),
                "plugin": str(plugins[label]),
                "plugin_sha256": hashlib.sha256(plugins[label].read_bytes()).hexdigest(),
                "qemu_build_identity": (
                    binary.parent.parent / "share/aos/crucible/qemu-build-identity.env"
                ).read_text(),
            }
            for label, binary in qemu.items()
        },
        "workloads": {},
    }
    labels = list(qemu)
    for workload, bios_name, horizon, loop_instructions in [
        ("ram", "bios.bin", args.ram_horizon, 7),
        ("io", "io-bios.bin", args.io_horizon, 8),
    ]:
        bios = args.fixtures / bios_name
        # Evaluate the independent arithmetic once before measuring any VM.
        reference_state(horizon, loop_instructions)
        samples = []
        expected = None
        for repeat in range(args.repetitions):
            order = labels if repeat % 2 == 0 else list(reversed(labels))
            for label in order:
                directory = args.output / f"{workload}-{repeat}-{label}"
                command = [
                    str(args.driver), str(qemu[label]), str(plugins[label]),
                    str(bios), str(horizon), str(directory), str(args.cpu),
                ]
                sample = json.loads(subprocess.check_output(command, text=True))
                sample.update(label=label, repeat=repeat, command=command)
                witness = {
                    key: sample[key]
                    for key in (
                        "raw_icount", "logical_tick", "registers",
                        "ram_sha256", "ram_prefix_hex", "status",
                    )
                }
                require_reference({"witness": witness}, horizon, loop_instructions)
                if expected is None:
                    expected = witness
                if witness != expected:
                    raise AssertionError(
                        f"state witness changed: {workload}, {label}, repeat {repeat}"
                    )
                samples.append(sample)
                (directory / "result.json").write_text(json.dumps(sample, indent=2) + "\n")
                print(json.dumps({
                    "workload": workload, "label": label, "repeat": repeat,
                    "seconds": sample["seconds"],
                }), flush=True)
        means = {
            label: statistics.mean(sample["seconds"] for sample in samples if sample["label"] == label)
            for label in labels
        }
        results["workloads"][workload] = {
            "bios": str(bios),
            "bios_sha256": hashlib.sha256(bios.read_bytes()).hexdigest(),
            "horizon": horizon,
            "samples": samples,
            "mean_seconds": means,
            "time_reduction_percent": (1 - means[labels[1]] / means[labels[0]]) * 100,
            "speedup": means[labels[0]] / means[labels[1]],
            "witness": expected,
            "independent_arithmetic_oracle": True,
        }
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()

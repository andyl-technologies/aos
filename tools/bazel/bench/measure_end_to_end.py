"""Measures real Nix evaluation, builds, tests and installation for boot identity.

Runs on a development host with an available Nix daemon. Every cold repetition
has a unique source edit and private cache namespace. Existing output reuse is
reported explicitly; resource files from cached builders are never fresh samples.
"""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS / "metadata"))
sys.path.insert(0, str(TOOLS / "tests"))
from measure_pilot import check_program


def copy_source(source, destination):
    def ignored(directory, names):
        parent = Path(directory)
        result = []
        for name in names:
            path = parent / name
            state = name in {".git", ".worktrees", ".direnv", "__pycache__", "node_modules"}
            cargo_output = name == "target" and (parent / "Cargo.toml").is_file()
            output_link = path.is_symlink() and (
                (name.startswith("bazel-") and path.is_dir())
                or name == "result" or name.startswith("result-")
            )
            if state or cargo_output or output_link:
                result.append(name)
        return result

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)


def measure(command, directory, name):
    started = time.monotonic()
    with (directory / (name + ".stdout")).open("wb") as output, (directory / (name + ".log")).open("wb") as log:
        process = subprocess.Popen(command, stdout=output, stderr=log)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode:
        print((directory / (name + ".log")).read_text(errors="replace")[-12000:], file=sys.stderr)
        raise RuntimeError(f"Nix measurement failed ({process.returncode}): {directory / name}")
    result = {
        "command": command,
        "wall_seconds": time.monotonic() - started,
        "client_user_seconds": usage.ru_utime,
        "client_system_seconds": usage.ru_stime,
        "client_peak_rss_kib": usage.ru_maxrss,
        "client_block_inputs": usage.ru_inblock,
        "client_block_outputs": usage.ru_oublock,
        "resource_scope": "Nix client and its waited descendants; daemon builders recorded separately",
        "load_average": list(os.getloadavg()),
    }
    return (directory / (name + ".stdout")).read_text().splitlines(), result


def builder_resources(output, mode, reused):
    """Reads each fresh builder once, excluding counters from reused outputs."""
    if reused:
        return {}

    names = ["benchmark-resources.json"]
    if mode == "bazel":
        names.extend(["bazel-action-resources.json", "bazel-action-metrics.json"])
    return {name: json.loads((output / "nix-support" / name).read_text()) for name in names}


def measure_series(options, helper, mode, repetition):
    identity = f"{repetition}-{mode}"
    root = options.scratch / identity
    workspace = root / "first-worktree"
    copy_source(options.root, workspace)
    package = Path("crates/boot/aos-boot-identity")
    salt = hashlib.sha256(f"{options.trial}:{repetition}".encode()).hexdigest()[:16]
    with (workspace / package / "src/lib.rs").open("a") as source:
        source.write(f"\n/// Identifies this fresh measurement source.\npub fn measurement_trial_{salt}() -> u32 {{ 17 }}\n")
    namespace = "end-to-end-" + hashlib.sha256(f"{options.trial}:{identity}".encode()).hexdigest()
    common = ["--max-jobs", "4", "--cores", "4", "--option", "substitute", "false",
              "--option", "extra-sandbox-paths", "/aos-build-cache/bazel=" + str(options.cache_root)]
    samples = []
    for scenario in ["cold", "warm", "implementation-edit", "public-api-edit", "second-worktree", "fresh-derivation"]:
        if scenario == "implementation-edit":
            with (workspace / package / "src/main.rs").open("a") as source:
                source.write("\n#[allow(dead_code)]\nfn measurement_private_edit() -> u32 { 1 }\n")
        elif scenario == "public-api-edit":
            with (workspace / package / "src/lib.rs").open("a") as source:
                source.write("\n/// Exposes the measurement's changed interface.\npub fn measurement_api_edit() -> u32 { 2 }\n")
        elif scenario == "second-worktree":
            relocated = root / "second-worktree"
            copy_source(workspace, relocated)
            workspace = relocated

        record = options.output / identity / scenario
        record.mkdir(parents=True)
        nonce = f"{options.trial}:{identity}:fresh" if scenario == "fresh-derivation" else ""
        command = [str(options.nix_tools / "nix-instantiate"), str(helper / "end_to_end.nix"),
                   "--argstr", "root", str(workspace), "--argstr", "mode", mode,
                   "--argstr", "cacheNamespace", namespace, "--argstr", "invocationNonce", nonce, *common]
        derivations, evaluation = measure(command, record, "evaluation")
        if len(derivations) != 1 or not derivations[0].endswith(".drv"):
            raise ValueError(f"expected one benchmark derivation: {derivations}")
        outputs = subprocess.check_output([
            str(options.nix_tools / "nix-store"), "--query", "--outputs", derivations[0],
        ], text=True).splitlines()
        if len(outputs) != 1:
            raise ValueError("benchmark package must have exactly one output")
        reused = Path(outputs[0]).exists()
        if scenario in {"cold", "fresh-derivation"} and reused:
            raise ValueError("fresh measurement would reuse an existing Nix output; choose a new trial")
        realised, realisation = measure([
            str(options.nix_tools / "nix-store"), "--realise", derivations[0], *common,
        ], record, "realisation")
        if realised != outputs:
            raise ValueError(f"unexpected realised outputs: {realised}")
        output = Path(outputs[0])
        check_program(output / "bin/aos-boot-identity", record)
        closure = subprocess.check_output([
            str(options.nix_tools / "nix-store"), "--query", "--requisites", str(output),
        ], text=True).splitlines()
        samples.append({
            "mode": mode, "repetition": repetition, "scenario": scenario,
            "derivation": derivations[0], "output": str(output),
            "evaluation": evaluation, "realisation": realisation,
            "wall_seconds": evaluation["wall_seconds"] + realisation["wall_seconds"],
            "nix_output_reused": reused, "fresh_builder_resources": builder_resources(output, mode, reused),
            "runtime_closure": closure,
        })
        print(f"{identity} {scenario}: {samples[-1]['wall_seconds']:.3f}s; output reused={reused}", flush=True)
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["root", "scratch", "output", "cache-root", "nix-tools"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--trial", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    options = parser.parse_args()
    if options.repetitions < 3:
        parser.error("at least three fresh repetitions are required")
    if options.scratch.resolve().is_relative_to(options.root.resolve()):
        parser.error("measurement scratch must be outside the source repository")
    options.scratch.mkdir()
    options.output.mkdir()
    memory_before = Path("/proc/meminfo").read_text()
    cpu_model = next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.partition(":")[0].strip() in {"model name", "Hardware", "Processor"}), None)
    source = options.scratch / "source"
    copy_source(options.root, source)
    options.root = source
    helper = options.scratch / "harness"
    copy_source(Path(__file__).parent, helper)
    samples = []
    for repetition in range(options.repetitions):
        modes = ["production", "bazel"] if repetition % 2 == 0 else ["bazel", "production"]
        for mode in modes:
            samples.extend(measure_series(options, helper, mode, repetition))
    distributions = defaultdict(list)
    for sample in samples:
        distributions[sample["mode"] + ":" + sample["scenario"]].append(sample["wall_seconds"])
    report = {
        "schema_version": 2,
        "scope": "Nix evaluation plus realisation of the installed boot identity production constructors",
        "workloads": {
            "production": {"driver": "rustc", "tests": ["library unit"]},
            "bazel": {"driver": "bazel", "tests": ["library unit", "CLI integration", "doctests"]},
        },
        "trial": options.trial, "platform": list(os.uname()), "cpu_count": os.cpu_count(),
        "available_cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_model": cpu_model,
        "memory_before": memory_before, "memory_after": Path("/proc/meminfo").read_text(),
        "nix_tools": str(options.nix_tools), "samples": samples,
        "harness_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in sorted(helper.glob("*")) if path.is_file()},
        "distributions": {name: {"samples": values, "median": statistics.median(values),
                                  "minimum": min(values), "maximum": max(values)}
                          for name, values in sorted(distributions.items())},
        "limitations": [
            "Compiler and dependency preparation are warm; each cold source and action cache namespace is fresh.",
            "The production baseline invokes rustc directly, not Cargo.",
            "The Bazel production constructor additionally runs CLI integration tests and doctests; test workloads differ.",
            "Recording wrapper and command-file preparation add benchmark overhead to both candidates.",
            "Package export and prerequisite builders are included in realisation wall time without separate resource records.",
            "JVM counters overlap the builder's adopted-child resources; cached timings are not fresh samples.",
            "Source copy and post-build runtime/closure validation are outside the measured intervals.",
            "Shared-host scheduling and filesystem page caches are uncontrolled.",
        ],
    }
    (options.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

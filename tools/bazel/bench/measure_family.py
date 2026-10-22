"""Measures matched connected-family libtest compilation and validates every case.

These compile-loop samples exclude Nix evaluation, dependency preparation and
installation. They supplement, rather than replace, end-to-end measurements.
Each mode has private compiler state and local disk caches. Every sample is
followed by untimed case discovery and execution against the qualified oracle.
"""

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
from urllib.parse import unquote, urlparse

from measure_pilot import copy_workspace, measure
from verify_cache import execution_events


MODES = ["cargo-incremental", "cargo-nonincremental-accache", "bazel-server"]
SCENARIOS = ["cold", "warm", "implementation-edit", "public-api-edit", "second-worktree", "fresh-build-directory"]


def bazel_binaries(events, targets):
    """Finds one current executable per requested successful libtest target."""
    sets = {}
    completed = {}
    finished = False
    for event in events:
        identity = event.get("id", {})
        if "namedSet" in identity:
            sets[identity["namedSet"]["id"]] = event["namedSetOfFiles"]
        if "buildFinished" in identity:
            finished = event["finished"]["exitCode"].get("code", 0) == 0
        label = identity.get("targetCompleted", {}).get("label")
        if label in targets:
            if label in completed or not event["completed"].get("success"):
                raise ValueError(f"ambiguous or failed test target: {label}")
            completed[label] = event["completed"]
    if not finished or set(completed) != set(targets):
        raise ValueError("missing successful requested libtest targets")
    binaries = {}
    for label, target in completed.items():
        roots = [item["id"] for group in target.get("outputGroup", [])
                 if group["name"] == "default" for item in group.get("fileSets", [])]
        visited = set()
        candidates = set()
        while roots:
            identifier = roots.pop()
            if identifier in visited:
                continue
            visited.add(identifier)
            entry = sets[identifier]
            roots.extend(item["id"] for item in entry.get("fileSets", []))
            for file in entry.get("files", []):
                if Path(file["name"]).name != label.split(":", 1)[1]:
                    continue
                uri = urlparse(file["uri"])
                if uri.scheme != "file" or uri.netloc:
                    raise ValueError("test artifacts must be local files")
                candidates.add(Path(unquote(uri.path)))
        if len(candidates) != 1:
            raise ValueError(f"expected exactly one executable for {label}: {candidates}")
        binaries[label.removesuffix("_binary")] = candidates.pop()
    return binaries


def cargo_binaries(events, packages):
    """Selects first-party test artifacts without conflating libraries and tests."""
    binaries = {}
    for event in events:
        if event.get("reason") != "compiler-artifact" or not event.get("executable") or not event["profile"]["test"]:
            continue
        target = event["target"]
        package = Path(event["manifest_path"]).parent.name
        if package not in packages or not set(target["kind"]) & {"lib", "test"}:
            continue
        name = "unit" if "lib" in target["kind"] else target["name"]
        label = f"//{packages[package]}:{name}"
        if label in binaries:
            raise ValueError(f"ambiguous Cargo test artifact: {label}")
        binaries[label] = Path(event["executable"])
    return binaries


def validate(binaries, expected, workspace, directory, environment):
    """Requires the qualified case inventory and successful runtime behavior."""
    if binaries.keys() != expected.keys():
        raise ValueError(f"compiled test targets differ: {binaries.keys() ^ expected.keys()}")
    for index, (label, binary) in enumerate(sorted(binaries.items())):
        cwd = workspace / label.split(":", 1)[0].removeprefix("//")
        for ignored in [False, True]:
            command = [str(binary), "--list", "--format=terse"] + (["--ignored"] if ignored else [])
            listing = subprocess.run(command, cwd=cwd, env=environment, check=True,
                                     capture_output=True, text=True, timeout=60)
            actual = sorted(line.removesuffix(": test") for line in listing.stdout.splitlines()
                            if line.endswith(": test"))
            oracle = expected[label]["ignored"] if ignored else expected[label]["executed"] + expected[label]["ignored"]
            if actual != sorted(oracle):
                raise ValueError(f"discovered test inventory differs: {label}")
        with (directory / f"validation-{index}.log").open("w") as log:
            subprocess.run([str(binary), "--test-threads=1"], cwd=cwd, env=environment,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        output = (directory / f"validation-{index}.log").read_text()
        passed = re.findall(r"^test (.+) \.\.\. ok$", output, re.MULTILINE)
        if sorted(passed) != sorted(expected[label]["executed"]):
            raise ValueError(f"executed test inventory differs: {label}")


def series(configuration, mode, repetition, scratch, output):
    """Keeps private mutable state per series and always shuts down its JVMs."""
    root = scratch / f"{repetition}-{mode}"
    root.mkdir()
    records = output / root.name
    records.mkdir()
    bazel = mode == "bazel-server"
    workspace = root / "first-worktree"
    copy_workspace(configuration["bazel_source" if bazel else "cargo_source"], workspace)
    if bazel:
        (workspace / "MODULE.bazel.lock").write_bytes(Path(configuration["prepared_lock"]).read_bytes())
    else:
        (workspace / ".cargo").mkdir(exist_ok=True)
        vendor = Path(configuration["vendor"])
        (workspace / ".cargo/config.toml").write_text(
            (vendor / ".cargo/config.toml").read_text().replace("@vendor@", str(vendor)))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CARGO_", "ACCACHE_", "RUST"))}
    environment.update(CARGO_HOME=str(root / "cargo-home"), CARGO_TARGET_DIR=str(root / "cargo-target"),
                       CARGO_INCREMENTAL="0" if "accache" in mode else "1", RUSTC=configuration["rustc"])
    if "accache" in mode:
        environment.update(RUSTC_WRAPPER=configuration["accache"], ACCACHE_DIR=str(root / "accache"),
                           ACCACHE_STATE_DIR=str(root / "accache-state"), ACCACHE_MANIFEST=configuration["accache_manifest"])
    expected = json.loads(Path(configuration["parity"]).read_text())["targets"]
    output_base = root / "bazel-first"
    servers = []
    samples = []
    try:
        for scenario in SCENARIOS:
            if scenario == "implementation-edit":
                path = workspace / configuration["packages"]["crucible-device"] / "src/lib.rs"
                with path.open("a") as file:
                    file.write("\n#[allow(dead_code)]\nfn measurement_private_edit() -> u32 { 1 }\n")
            elif scenario == "public-api-edit":
                path = workspace / configuration["packages"]["crucible-determinism"] / "src/lib.rs"
                with path.open("a") as file:
                    file.write("\n/// Exposes the measurement's changed shared interface.\npub fn measurement_api_edit() -> u32 { 2 }\n")
            elif scenario == "second-worktree":
                relocated = root / "second-worktree"
                copy_workspace(workspace, relocated)
                workspace = relocated
                output_base = root / "bazel-second"
            elif scenario == "fresh-build-directory":
                output_base = root / "bazel-fresh"
                environment["CARGO_TARGET_DIR"] = str(root / "cargo-fresh-target")
            directory = records / scenario
            directory.mkdir()
            if bazel:
                prefix = [sys.executable, configuration["launcher"], "--config", configuration["bazel_config"],
                          "--workspace", str(workspace), "--output-base", str(output_base), "--nix-sandbox"]
                if prefix not in servers:
                    servers.append(prefix)
                command = prefix + ["--cache", str(root / "bazel-cache"), "--metrics", str(directory / "launcher.json"),
                                    "--", "build"] + configuration["targets"] + [
                                        "--build_event_json_file=" + str(directory / "events.json"),
                                        "--execution_log_json_file=" + str(directory / "execution.json")]
            else:
                command = [configuration["cargo"], "test", "--manifest-path", "crates/Cargo.toml", "--frozen", "--offline",
                           "--jobs", str(configuration["jobs"]), "--lib", "--tests", "--no-run", "--message-format=json"]
                for package in sorted(configuration["packages"]):
                    command.extend(["-p", package])
            sample = measure(command, workspace, environment, directory / "command.log")
            sample.update(mode=mode, repetition=repetition, scenario=scenario)
            if bazel:
                events = [json.loads(line) for line in (directory / "events.json").read_text().splitlines()]
                binaries = bazel_binaries(events, configuration["targets"])
                (directory / "evidence").mkdir()
                (directory / "evidence/execution.json").symlink_to(directory / "execution.json")
                sample["actions"] = dict(Counter(event["mnemonic"] + (":restored" if event["cacheHit"] else ":executed")
                                                 for event in execution_events(directory)))
                sample["jvm"] = json.loads((directory / "launcher.json").read_text())
                sample["resource_scope"] = "waited launcher/client descendants; private JVM resources recorded separately"
            else:
                events = [json.loads(line) for line in (directory / "command.log").read_text().splitlines() if line.startswith("{")]
                binaries = cargo_binaries(events, configuration["packages"])
                sample["cargo_artifacts"] = dict(Counter("fresh" if event["fresh"] else "rebuilt"
                                                        for event in events if event.get("reason") == "compiler-artifact"))
            validate(binaries, expected, workspace, directory, environment)
            sample["validated_cases"] = sum(len(item["executed"]) for item in expected.values())
            samples.append(sample)
        if "accache" in mode:
            result = subprocess.run([configuration["accache"], "stats"], env=environment, check=True, capture_output=True, text=True)
            (records / "accache-stats.json").write_text(result.stdout)
            if not json.loads(result.stdout).get("miss", 0):
                raise ValueError("accache baseline admitted no compiler actions")
        return samples
    finally:
        failed = sys.exc_info()[0] is not None
        errors = []
        for prefix in servers:
            try:
                subprocess.run(prefix + ["--", "shutdown"], check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError) as error:
                errors.append(str(error))
        if errors:
            message = "private server shutdown failed: " + "; ".join(errors)
            if failed:
                print(message, file=sys.stderr)
            else:
                raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["configuration", "scratch", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    options = parser.parse_args()
    if options.repetitions < 3:
        parser.error("at least three repetitions are required")
    configuration = json.loads(options.configuration.read_text())
    options.scratch.mkdir()
    options.output.mkdir(parents=True, exist_ok=True)
    samples = []
    for repetition in range(options.repetitions):
        for mode in MODES[repetition % len(MODES):] + MODES[:repetition % len(MODES)]:
            print(f"measuring repetition {repetition + 1}: {mode}", flush=True)
            samples.extend(series(configuration, mode, repetition, options.scratch, options.output))
    groups = defaultdict(list)
    for sample in samples:
        groups[sample["mode"] + ":" + sample["scenario"]].append(sample["wall_seconds"])
    report = {
        "schema_version": 1, "scope": "connected device-family libtest compilation; validation is untimed; excludes Nix evaluation/preparation/installation",
        "configuration": configuration, "platform": list(os.uname()), "cpu_count": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "memory": Path("/proc/meminfo").read_text(),
        "samples": samples, "budgets": "not established; requires end-to-end acceptance measurements",
        "distributions": {name: {"samples": values, "median": statistics.median(values), "minimum": min(values), "maximum": max(values)}
                          for name, values in sorted(groups.items())},
    }
    (options.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

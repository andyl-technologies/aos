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
import statistics
import subprocess
import sys

from measure_pilot import copy_workspace, measure
from verify_cache import execution_events
from family_libtest import bazel_binaries, validate


MODES = ["cargo-incremental", "cargo-nonincremental-accache", "cargo-incremental-debug0", "bazel-server"]
SCENARIOS = ["cold", "warm", "implementation-edit", "public-api-edit", "second-worktree", "fresh-build-directory"]


def cargo_binaries(events, packages):
    """Selects first-party test artifacts without conflating libraries and tests."""
    binaries = {}
    for event in events:
        if event.get("reason") != "compiler-artifact" or not event.get("executable") or not event["profile"]["test"]:
            continue
        target = event["target"]
        package = Path(event["manifest_path"]).parent.name
        if package not in packages or not set(target["kind"]) & {"lib", "bin", "test"}:
            continue
        name = ("unit" if "lib" in target["kind"] else
                "bin_" + target["name"] if "bin" in target["kind"] else target["name"])
        label = f"//{packages[package]}:{name}"
        if label in binaries:
            raise ValueError(f"ambiguous Cargo test artifact: {label}")
        binaries[label] = Path(event["executable"])
    return binaries


def compilation_profile(events, binaries, incremental):
    """Records the actual Cargo artifact profiles instead of assuming defaults."""
    profiles = {(event["profile"]["opt_level"], event["profile"]["debuginfo"],
                 event["profile"]["debug_assertions"], event["profile"]["overflow_checks"])
                for event in events if event.get("reason") == "compiler-artifact"
                and event.get("executable") in {str(binary) for binary in binaries.values()}}
    if len(profiles) != 1:
        raise ValueError(f"measured Cargo test artifacts have ambiguous profiles: {profiles}")
    optimization, debug, assertions, overflow = profiles.pop()
    return {"opt_level": optimization, "debug": debug, "debug_assertions": assertions,
            "overflow_checks": overflow, "incremental": incremental}


def validate_profile(profile, configuration):
    """Rejects profile drift in workloads requiring a matched comparison."""
    if configuration.get("require_matched_profiles", False):
        expected = configuration["bazel_compilation_profile"]
        actual = {key: value for key, value in profile.items() if key != "incremental"}
        if actual != expected:
            raise ValueError(f"measured compilation profile differs: {actual!r} != {expected!r}")


def validate_bazel_profile(configuration):
    """Requires explicit launcher flags for every matched profile setting."""
    if not configuration.get("require_matched_profiles", False):
        return
    profile = configuration["bazel_compilation_profile"]
    flags = json.loads(Path(configuration["bazel_config"]).read_text())["rustc_flags"]
    settings = {
        "opt-level": str(profile["opt_level"]),
        "debuginfo": str(profile["debug"]),
        "debug-assertions": "yes" if profile["debug_assertions"] else "no",
        "overflow-checks": "yes" if profile["overflow_checks"] else "no",
    }
    for setting, value in settings.items():
        prefix = "-C" + setting + "="
        actual = [flag for flag in flags if flag.startswith(prefix)]
        if actual != [prefix + value]:
            raise ValueError(f"Bazel launcher profile must declare {prefix + value}: {actual!r}")


def record_cargo_commands(log, output, require_commands=False):
    """Retains Cargo's verbose compiler calls without interpreting shell text."""
    commands = []
    for line in log.read_text().splitlines():
        value = line.strip()
        if not value.startswith("Running `") or " --crate-name " not in value:
            continue
        if not value.endswith("`"):
            raise ValueError("unterminated Cargo compiler command")
        commands.append(value.removeprefix("Running `").removesuffix("`"))

    if require_commands and not commands:
        raise ValueError("cold Cargo measurement retained no compiler commands")
    output.write_text("".join(command + "\n" for command in commands))
    return len(commands)


def apply_edit(workspace, configuration, scenario):
    """Changes a declared first-party input without allowing paths outside it."""
    defaults = {
        "implementation-edit": "crates/crucible/engine/crucible-device/src/lib.rs",
        "public-api-edit": "crates/crucible/engine/crucible-determinism/src/lib.rs",
    }
    relative = Path(configuration.get("edits", defaults)[scenario])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("measurement edit must name a relative source file")
    path = workspace / relative
    if not path.resolve().is_relative_to(workspace.resolve()) or not path.is_file():
        raise ValueError("measurement edit source is missing or outside the workspace")
    declaration = ("#[allow(dead_code)]\nfn measurement_private_edit() -> u32 { 1 }"
                   if scenario == "implementation-edit" else
                   "/// Exposes the measurement's changed shared interface.\npub fn measurement_api_edit() -> u32 { 2 }")
    with path.open("a") as file:
        file.write("\n" + declaration + "\n")


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
    environment.update(configuration.get("cargo_environment", {}))
    if mode == "cargo-incremental-debug0":
        # Match rules_rust's fastbuild profile without changing the existing
        # development-profile baseline. Cargo's test profile inherits dev, but
        # set both explicitly so the recorded comparison is unambiguous.
        for profile in ["DEV", "TEST"]:
            environment["CARGO_PROFILE_" + profile + "_DEBUG"] = "0"
            environment["CARGO_PROFILE_" + profile + "_OPT_LEVEL"] = "0"
    if "accache" in mode:
        environment.update(RUSTC_WRAPPER=configuration["accache"], ACCACHE_DIR=str(root / "accache"),
                           ACCACHE_STATE_DIR=str(root / "accache-state"), ACCACHE_MANIFEST=configuration["accache_manifest"])
    expected = json.loads(Path(configuration["parity"]).read_text())["targets"]
    output_base = root / "bazel-first"
    servers = []
    samples = []
    try:
        for scenario in SCENARIOS:
            print(f"measuring repetition {repetition}: {mode}: {scenario}", flush=True)
            if scenario in {"implementation-edit", "public-api-edit"}:
                apply_edit(workspace, configuration, scenario)
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
                           "--jobs", str(configuration["jobs"]), "--lib", "--tests", "--no-run", "--message-format=json", "--verbose"]
                for package in sorted(configuration["packages"]):
                    command.extend(["-p", package])
                command.extend(configuration.get("cargo_flags", []))
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
                sample["compilation_profile"] = dict(configuration.get("bazel_compilation_profile", {
                    "opt_level": "0", "debug": 0, "debug_assertions": True, "overflow_checks": True,
                }), incremental=False)
            else:
                sample["compiler_invocation_count"] = record_cargo_commands(
                    directory / "command.log", directory / "cargo-compiler-commands.txt", require_commands=scenario == "cold")
                events = [json.loads(line) for line in (directory / "command.log").read_text().splitlines() if line.startswith("{")]
                binaries = cargo_binaries(events, configuration["packages"])
                sample["compilation_profile"] = compilation_profile(events, binaries, "accache" not in mode)
                sample["cargo_artifacts"] = dict(Counter("fresh" if event["fresh"] else "rebuilt"
                                                        for event in events if event.get("reason") == "compiler-artifact"))
            validate_profile(sample["compilation_profile"], configuration)
            validate(binaries, expected, workspace, directory, environment,
                     case_runner=configuration.get("case_runner"), policy=configuration.get("test_policy"),
                     jobs=configuration["jobs"])
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
    parser.add_argument("--mode", choices=MODES, action="append",
                        help="Measure only this mode; repeat to compare selected modes.")
    options = parser.parse_args()
    if options.repetitions < 3:
        parser.error("at least three repetitions are required")
    modes = options.mode or MODES
    if len(set(modes)) != len(modes):
        parser.error("measurement modes must not repeat")
    configuration = json.loads(options.configuration.read_text())
    validate_bazel_profile(configuration)
    options.scratch.mkdir()
    options.output.mkdir(parents=True, exist_ok=True)
    samples = []
    for repetition in range(options.repetitions):
        for mode in modes[repetition % len(modes):] + modes[:repetition % len(modes)]:
            print(f"measuring repetition {repetition + 1}: {mode}", flush=True)
            samples.extend(series(configuration, mode, repetition, options.scratch, options.output))
    groups = defaultdict(list)
    for sample in samples:
        groups[sample["mode"] + ":" + sample["scenario"]].append(sample["wall_seconds"])
    report = {
        "schema_version": 1, "scope": configuration.get("scope", "connected device-family libtest compilation") + "; validation is untimed; excludes Nix evaluation/preparation/installation",
        "configuration": configuration, "platform": list(os.uname()), "cpu_count": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "memory": Path("/proc/meminfo").read_text(),
        "samples": samples, "budgets": "not established; requires end-to-end acceptance measurements",
        "distributions": {name: {"samples": values, "median": statistics.median(values), "minimum": min(values), "maximum": max(values)}
                          for name, values in sorted(groups.items())},
    }
    (options.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

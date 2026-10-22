"""Measures real boot-identity compile commands before a production cutover.

Cargo remains a temporary migration oracle. These measurements exclude Nix
evaluation, dependency preparation, and installation; the separate cache proof
qualifies actual independent Nix executions. Every sample executes its command
and validates the resulting program rather than restoring a timing result.
"""

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

from export_packages import completed_manifests
from verify_cache import execution_events


PACKAGE = "crates/aos/boot/aos-boot-identity"
LABEL = "//" + PACKAGE + ":package"
MODES = ["cargo-incremental", "bazel", "cargo-nonincremental-accache", "cargo-incremental-debug0", "bazel-server"]


def measure(command, directory, environment, output):
    """Collects resource usage for this invocation and its waited descendants."""
    started = time.monotonic()
    with output.open("wb") as log:
        process = subprocess.Popen(command, cwd=directory, env=environment,
                                   stdout=log, stderr=subprocess.STDOUT)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode:
        print("\n".join(output.read_text(errors="replace").splitlines()[-80:]), file=sys.stderr)
        raise RuntimeError(f"measurement command failed ({process.returncode}); see {output}")
    return {
        "command": command,
        "wall_seconds": time.monotonic() - started,
        "user_seconds": usage.ru_utime,
        "system_seconds": usage.ru_stime,
        "peak_rss_kib": usage.ru_maxrss,
        "block_inputs": usage.ru_inblock,
        "block_outputs": usage.ru_oublock,
        "load_average": list(os.getloadavg()),
    }


def copy_workspace(source, destination):
    """Creates a writable tree without carrying execution state between roots."""
    shutil.copytree(source, destination, symlinks=True,
                    ignore=shutil.ignore_patterns("bazel-*", "target", ".git", ".worktrees", "__pycache__"))
    for directory, _, files in os.walk(destination):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o200)


def check_program(executable, directory):
    """Checks accepted and rejected boot identities outside the timed compile."""
    command_line = directory / "cmdline"
    command_line.write_text(
        "root=/dev/mapper/root ro systemd.verity=yes "
        "systemd.verity_root_data=/dev/disk/by-partlabel/root-a "
        "systemd.verity_root_hash=/dev/disk/by-partlabel/root-a-hash "
        "roothash=" + "0123456789abcdef" * 4 + " rd.luks=0\n"
    )
    subprocess.run([str(executable), str(command_line)], check=True, capture_output=True)
    command_line.write_text("root=/dev/disk/by-partlabel/root-a ro\n")
    rejected = subprocess.run([str(executable), str(command_line)], capture_output=True, text=True)
    if rejected.returncode != 1 or "rejected normal boot" not in rejected.stderr:
        raise ValueError("measured executable did not reject the invalid boot identity")


def run_series(configuration, mode, repetition, scratch, output):
    """Shuts down every private server even when a measurement fails."""
    servers = []
    try:
        return measure_series(configuration, mode, repetition, scratch, output, servers)
    finally:
        active_failure = sys.exc_info()[0] is not None
        failures = []
        for prefix in servers:
            try:
                subprocess.run(prefix + ["--", "shutdown"], check=True, stdout=subprocess.DEVNULL)
            except (OSError, subprocess.CalledProcessError) as error:
                failures.append(str(error))
        if failures:
            message = "private server shutdown failed: " + "; ".join(failures)
            if active_failure:
                print(message, file=sys.stderr)
            else:
                raise RuntimeError(message)


def measure_series(configuration, mode, repetition, scratch, output, servers):
    """Measures edits and relocation with private mutable state per series."""
    identity = f"{repetition}-{mode}"
    root = scratch / identity
    root.mkdir()
    records = output / identity
    records.mkdir()
    bazel = mode.startswith("bazel")
    bazel_config = configuration["bazel_config"]
    if mode == "bazel-server":
        policy = json.loads(Path(bazel_config).read_text())
        policy["batch"] = False
        bazel_config = root / "server-config.json"
        bazel_config.write_text(json.dumps(policy))
    bazel_config = str(bazel_config)
    workspace = root / "first-worktree"
    copy_workspace(configuration["bazel_source" if bazel else "cargo_source"], workspace)
    if bazel:
        (workspace / "MODULE.bazel.lock").write_bytes(Path(configuration["prepared_lock"]).read_bytes())
    else:
        (workspace / ".cargo").mkdir(exist_ok=True)
        vendor = Path(configuration["vendor"])
        (workspace / ".cargo/config.toml").write_text(
            (vendor / ".cargo/config.toml").read_text().replace("@vendor@", str(vendor)))

    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("CARGO_", "ACCACHE_"))
        and key not in {"RUSTC_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN"}
    }
    environment.update(CARGO_HOME=str(root / "cargo-home"), CARGO_TARGET_DIR=str(root / "cargo-target"),
                       CARGO_INCREMENTAL="0" if "nonincremental" in mode else "1", RUSTC=configuration["rustc"])
    if "debug0" in mode:
        environment["CARGO_PROFILE_DEV_DEBUG"] = "0"
    if "accache" in mode:
        environment.update(RUSTC_WRAPPER=configuration["accache"], ACCACHE_DIR=str(root / "accache"),
                           ACCACHE_STATE_DIR=str(root / "accache-state"),
                           ACCACHE_MANIFEST=configuration["accache_manifest"])
    output_base = root / "bazel-first"
    samples = []
    for scenario in ["cold", "warm", "implementation-edit", "public-api-edit", "second-worktree", "fresh-build-directory"]:
        if scenario == "implementation-edit":
            path = workspace / PACKAGE / "src/main.rs"
            with path.open("a") as source:
                source.write("\n#[allow(dead_code)]\nfn measurement_private_edit() -> u32 { 1 }\n")
        elif scenario == "public-api-edit":
            path = workspace / PACKAGE / "src/lib.rs"
            with path.open("a") as source:
                source.write("\n/// Exposes the measurement's changed library interface.\npub fn measurement_api_edit() -> u32 { 2 }\n")
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
            prefix = [sys.executable, configuration["launcher"], "--config", bazel_config,
                      "--workspace", str(workspace), "--output-base", str(output_base), "--nix-sandbox"]
            if mode == "bazel-server" and prefix not in servers:
                servers.append(prefix)
            command = prefix + ["--cache", str(root / "bazel-cache"),
                       "--metrics", str(directory / "launcher.json"), "--", "build", LABEL,
                       "--execution_log_json_file=" + str(directory / "execution.json"),
                       "--build_event_json_file=" + str(directory / "events.json")]
        else:
            command = [configuration["cargo"], "build", "--manifest-path", "crates/Cargo.toml",
                       "--frozen", "--offline", "--jobs", str(configuration["jobs"]),
                       "-p", "aos-boot-identity", "--bin", "aos-boot-identity", "--message-format=json"]
        sample = measure(command, workspace, environment, directory / "command.log")
        sample.update(mode=mode, repetition=repetition, scenario=scenario)
        sample["compiler_environment"] = {key: value for key, value in environment.items()
                                          if key.startswith(("CARGO_", "ACCACHE_", "RUST"))}
        if bazel:
            if mode == "bazel-server":
                metrics = json.loads((directory / "launcher.json").read_text())
                sample["server_before"] = metrics["server_before"]
                sample["server_after"] = metrics["server_after"]
                sample["resource_scope"] = "waited launcher/client descendants; JVM resources recorded separately"
            events = [json.loads(line) for line in (directory / "events.json").read_text().splitlines()]
            manifests = completed_manifests(events)
            if len(manifests) != 1:
                raise ValueError("measured build did not export exactly one current package manifest")
            manifest = json.loads(manifests[0].read_text())
            artifact, = manifest["artifacts"]
            executable = manifests[0].parent / artifact["source"]
            # Reuse the existing execution-log parser without retaining a build tree.
            log_root = directory / "evidence"
            log_root.mkdir()
            (log_root / "execution.json").symlink_to(directory / "execution.json")
            sample["actions"] = dict(Counter(
                event["mnemonic"] + (":restored" if event["cacheHit"] else ":executed")
                for event in execution_events(directory)
            ))
        else:
            events = []
            for line in (directory / "command.log").read_text().splitlines():
                if line.startswith("{"):
                    event = json.loads(line)
                    if event.get("reason") == "compiler-artifact":
                        events.append(event)
            sample["cargo_artifacts"] = dict(Counter("fresh" if event["fresh"] else "rebuilt" for event in events))
            executable = Path(environment["CARGO_TARGET_DIR"]) / "debug/aos-boot-identity"
        check_program(executable, directory)
        samples.append(sample)
    if "accache" in mode:
        with (records / "accache-stats.txt").open("wb") as stats:
            subprocess.run([configuration["accache"], "stats"], env=environment, stdout=stats, check=True)
        counts = json.loads((records / "accache-stats.txt").read_text())
        if not counts.get("miss", 0):
            raise ValueError("accache baseline did not admit any compiler action; inspect bypass diagnostics")
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    options = parser.parse_args()
    if options.repetitions < 3:
        parser.error("at least three fresh repetitions are required")
    configuration = json.loads(options.configuration.read_text())
    options.scratch.mkdir()
    options.output.mkdir(parents=True, exist_ok=True)
    samples = []
    for repetition in range(options.repetitions):
        # Rotate mode order to avoid assigning the same scheduling position to
        # one build system in every repetition on a shared builder.
        modes = MODES[repetition % len(MODES):] + MODES[:repetition % len(MODES)]
        for mode in modes:
            print(f"measuring repetition {repetition + 1}: {mode}", flush=True)
            samples.extend(run_series(configuration, mode, repetition, options.scratch, options.output))
    groups = defaultdict(list)
    for sample in samples:
        groups[sample["mode"] + ":" + sample["scenario"]].append(sample["wall_seconds"])
    report = {
        "schema_version": 1,
        "scope": "boot-identity compile commands; excludes Nix evaluation, preparation, and installation",
        "configuration": configuration,
        "platform": list(os.uname()),
        "cpu_count": os.cpu_count(),
        "samples": samples,
        "distributions": {name: {"samples": values, "median": statistics.median(values),
                                  "minimum": min(values), "maximum": max(values)} for name, values in sorted(groups.items())},
        "budgets": "not established; requires family end-to-end acceptance measurements",
    }
    (options.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

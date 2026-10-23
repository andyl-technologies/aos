"""Runs Bazel with an offline AOS toolchain and an allowlisted environment.

Nix builds use a private output base. Direct development reuses only the output
base selected for that worktree/configuration; independent builds share disk
action results, never execution trees. No remote cache or execution is enabled.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time


def shadow_workspace(source, output_base, lock):
    """Keeps generated locks and Bazel output links outside the source checkout."""
    destination = output_base.parent / "workspace"
    destination.mkdir(exist_ok=True)
    marker = destination / ".aos-shadow-workspace"
    if marker.exists():
        if marker.read_text() != str(source):
            raise ValueError("output base belongs to another source checkout")
    elif any(destination.iterdir()):
        raise ValueError("refusing an unmanaged development workspace")
    marker.write_text(str(source))

    excluded = {".git", ".worktrees", ".claude", ".direnv", ".agents", ".codex", "MODULE.bazel.lock"}
    entries = {
        child.name: child for child in source.iterdir()
        if child.name not in excluded and not child.name.startswith(("bazel-", "result"))
    }
    for child in destination.iterdir():
        if child.is_symlink() and child.name not in entries:
            child.unlink()
    for name, child in entries.items():
        target = destination / name
        if target.is_symlink() and target.readlink() != child:
            target.unlink()
        if not target.is_symlink():
            target.symlink_to(child, target_is_directory=child.is_dir())

    (destination / "MODULE.bazel.lock").write_bytes(lock.read_bytes())
    return destination


def server_usage(output_base):
    """Samples the private JVM separately from the waited command-line client."""
    try:
        pid = int((output_base / "server/server.pid.txt").read_text().strip())
        process = Path("/proc") / str(pid)
        fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
        status = {}
        for line in (process / "status").read_text().splitlines():
            name, _, value = line.partition(":")
            if name in {"VmRSS", "VmHWM"}:
                status[name] = int(value.split()[0])
        ticks = os.sysconf("SC_CLK_TCK")
        return {
            "pid": pid,
            "user_seconds": int(fields[11]) / ticks,
            "system_seconds": int(fields[12]) / ticks,
            "children_user_seconds": int(fields[13]) / ticks,
            "children_system_seconds": int(fields[14]) / ticks,
            "rss_kib": status.get("VmRSS"),
            "peak_rss_kib": status.get("VmHWM"),
        }
    except (OSError, ValueError, IndexError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output-base", required=True, type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--batch", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--prepare-lock", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--nix-sandbox", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--shadow-workspace", action="store_true")
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--metrics", type=Path)
    parser.add_argument("--rust-project-output", type=Path)
    parser.add_argument("--rust-project-package", action="append", default=[])
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if options.rust_project_package and not options.rust_project_output:
        parser.error("rust-project packages require an editor output")
    config = json.loads(options.config.read_text())
    arguments = options.arguments
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    if not arguments:
        parser.error("a Bazel command is required")
    if arguments[0] not in {"build", "test", "run", "query", "cquery", "aquery", "mod", "info", "clean", "version", "help", "shutdown"}:
        parser.error("unsupported offline Bazel command")
    if config.get("compile_only"):
        if not config.get("target_platform"):
            parser.error("compile-only configuration requires an explicit target platform")
        if arguments[0] in {"test", "run"}:
            parser.error("compile-only configuration requires explicit external target execution")
    batch = config.get("batch", True) if options.batch is None else options.batch
    if arguments[0] == "shutdown" and batch:
        parser.error("shutdown requires a configuration with batch=false")

    forbidden = ("--remote_", "--remote-", "--experimental_remote_", "--override_repository",
                 "--override_module", "--repo_env", "--action_env", "--host_action_env",
                 "--spawn_strategy", "--strategy", "--modify_execution_info",
                 "--registry", "--inject_repository", "--extra_toolchains", "--extra_execution_platforms",
                 "--crosstool_top", "--host_crosstool_top", "--workspace_status_command",
                 "--bes_", "--genrule_strategy", "--test_strategy",
                 "--flagfile", "--flag_alias", "--default_override",
                 "--dynamic_local_strategy", "--dynamic_remote_strategy", "--sandbox_add_mount_pair",
                 "--sandbox_block_path")
    bazel_arguments = arguments[:arguments.index("--")] if "--" in arguments else arguments
    if any(argument.startswith(forbidden) for argument in bazel_arguments):
        parser.error("toolchain/environment overrides and remote services are not supported")

    output_base = options.output_base.resolve()
    output_base.mkdir(parents=True, exist_ok=True)
    if options.rust_project_output:
        if arguments[0] != "build" or options.prepare_lock:
            parser.error("rust-project export requires an ordinary build command")
        arguments.extend([
            "--aspects=@rules_rust//rust:defs.bzl%rust_analyzer_aspect",
            "--output_groups=default,rust_analyzer_crate_spec,rust_analyzer_proc_macro_dylib,rust_analyzer_src,rust_generated_srcs",
            f"--build_event_json_file={output_base / 'rust-project-events.json'}",
        ])
    # Serialize shadow-tree updates as well as Bazel itself. A lock beside the
    # output base survives `clean --expunge`, which removes the output base.
    output_lock = (output_base.parent / ".aos-launcher.lock").open("a")
    fcntl.flock(output_lock, fcntl.LOCK_EX)
    workspace = options.workspace.resolve()
    if options.shadow_workspace:
        if not options.lock:
            parser.error("a prepared lock is required for the development workspace")
        workspace = shadow_workspace(workspace, output_base, options.lock)
    environment = {
        "PATH": config["path"],
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "1",
        "HOME": str(output_base / "home"),
        "TMPDIR": str(output_base / "tmp"),
        "USER": "aos-build",
    }
    for directory in [environment["HOME"], environment["TMPDIR"]]:
        Path(directory).mkdir(exist_ok=True)

    version = subprocess.run([config["bazel"], "--version"], cwd=workspace,
                             env=environment, capture_output=True, text=True, check=True)
    expected_version = re.escape(config["bazel_version"])
    if not re.fullmatch(rf"bazel {expected_version}(?:- \([^\n]*\))?\s*", version.stdout):
        parser.error(f"expected AOS Bazel {config['bazel_version']}, got {version.stdout.strip()!r}")

    policy = [
        "--enable_bzlmod", "--repository_disable_download",
        "--lockfile_mode=update" if options.prepare_lock else "--lockfile_mode=error",
        f"--registry=file://{config['registry']}",
        "--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1",
        f"--repo_env=BAZEL_SH={config['bash']}",
    ]
    for name, path in sorted(config["modules"].items()):
        policy.append(f"--override_module={name}={path}")
    for name, path in sorted(config["repositories"].items()):
        policy.append(f"--override_repository={name}={path}")
    if arguments[0] == "shutdown":
        # Shutdown is a client lifecycle command, with no repository analysis
        # or compilation options. The output-base lock still serializes it.
        policy = []

    if arguments[0] in {"build", "test", "run", "cquery", "aquery"}:
        if config.get("target_platform"):
            policy.append(f"--platforms={config['target_platform']}")
        if config.get("compile_only"):
            # Bazel 9 resolves a test execution platform even for `build`.
            # Admit the foreign platform for analysis only; test/run were
            # rejected above. Compiler actions still require native tools.
            policy.append(f"--extra_execution_platforms={config['target_platform']}")
        if config.get("rustc_flags"):
            policy.append("--@rules_rust//rust/settings:extra_rustc_flags=" + ",".join(config["rustc_flags"]))
        if config.get("dependency_profile"):
            policy.append(f"--//tools/bazel/rules:dependency_profile={config['dependency_profile']}")
        policy.extend([
            "--incompatible_strict_action_env", "--stamp=false", "--spawn_strategy=sandboxed",
            "--sandbox_block_path=/bin/sh",
            "--@rules_rust//rust/settings:clippy.toml=//tools/bazel/rules:clippy.toml",
            "--@rules_rust//rust/settings:rustfmt.toml=//tools/bazel/rules:rustfmt.toml",
            # Nix already isolates the network. Reusing that namespace also
            # avoids Bazel trying to mount sysfs at /sys, absent inside Nix.
            "--sandbox_default_allow_network=true" if options.nix_sandbox
            else "--sandbox_default_allow_network=false",
            f"--action_env=PATH={config['path']}", "--action_env=LANG=C",
            "--action_env=LC_ALL=C", "--action_env=TZ=UTC", "--action_env=SOURCE_DATE_EPOCH=1",
            f"--host_action_env=PATH={config['path']}",
            "--test_output=errors",
            f"--shell_executable={config['bash']}",
            f"--jobs={config['jobs']}", "--local_resources=memory=2048",
            "--remote_cache=", "--remote_executor=",
        ])
        policy.append(f"--disk_cache={options.cache.resolve()}" if options.cache else "--disk_cache=")
        if not options.cache:
            policy.append("--nocache_test_results")

    if "--" in arguments:
        split = arguments.index("--")
        arguments = arguments[:split] + policy + arguments[split:]
    else:
        arguments += policy

    command = [
        config["bazel"],
    ] + (["--batch"] if batch else ["--max_idle_secs=60"]) + [
        # Large builders must not give every small JVM the host's full CPU
        # count or default heap. Keep startup/JIT/GC within the selected jobs.
        "--host_jvm_args=-Xmx2g",
        f"--host_jvm_args=-XX:ActiveProcessorCount={config['jobs']}",
        f"--output_base={output_base}",
        f"--output_user_root={output_base / 'user'}",
        f"--server_javabase={config['jdk']}",
        "--host_jvm_args=-Dfile.encoding=UTF-8",
        "--nosystem_rc", "--nohome_rc", "--noworkspace_rc",
    ] + arguments
    started_ns = time.time_ns()
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    server_before = server_usage(output_base) if not batch else None
    try:
        status = subprocess.call(command, cwd=workspace, env=environment)
        if status == 0 and options.rust_project_output:
            exporter = [
                sys.executable, config["rust_project_exporter"],
                "--events", str(output_base / "rust-project-events.json"),
                "--workspace", str(options.workspace.resolve()),
                "--execution-root", str(output_base / "execroot/_main"),
                "--output-base", str(output_base),
                "--toolchain", config["repositories"]["aos_tools"],
                "--output", str(options.rust_project_output.resolve()),
            ]
            for package in options.rust_project_package:
                exporter.extend(["--workspace-package", package])
            status = subprocess.call(exporter, cwd=workspace, env=environment)
    finally:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        if options.metrics:
            options.metrics.write_text(json.dumps({
                "schema_version": 1,
                "started_unix_ns": started_ns,
                "finished_unix_ns": time.time_ns(),
                "wall_seconds": time.monotonic() - started,
                "user_seconds": after.ru_utime - before.ru_utime,
                "system_seconds": after.ru_stime - before.ru_stime,
                "peak_rss_kib": after.ru_maxrss,
                # The persistent JVM is not a waited child of this launcher.
                # Its CPU counters and memory must not disappear from reports.
                "server_before": server_before,
                "server_after": server_usage(output_base) if not batch else None,
                "block_inputs": after.ru_inblock - before.ru_inblock,
                "block_outputs": after.ru_oublock - before.ru_oublock,
                "uid": os.getuid(),
                "pid": os.getpid(),
                "uid_map": Path("/proc/self/uid_map").read_text(),
                "namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ["mnt", "pid", "user", "net"]},
                "output_base_inode": output_base.stat().st_ino,
                "output_base": str(output_base),
                "disk_cache": str(options.cache) if options.cache else None,
                "bazel_version": config["bazel_version"],
                "command": command,
            }, indent=2, sort_keys=True) + "\n")
        output_lock.close()
    raise SystemExit(status)


if __name__ == "__main__":
    main()

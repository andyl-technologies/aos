"""Runs Bazel with an offline AOS toolchain and an allowlisted environment.

Nix builds use a private output base. Direct development reuses only the output
base selected for that worktree/configuration; independent builds share disk
action results, never execution trees. No remote cache or execution is enabled.
"""

import argparse
import fcntl
import json
from pathlib import Path
import re
import subprocess


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output-base", required=True, type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--prepare-lock", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--nix-sandbox", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--shadow-workspace", action="store_true")
    parser.add_argument("--lock", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    config = json.loads(options.config.read_text())
    arguments = options.arguments
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    if not arguments:
        parser.error("a Bazel command is required")
    if arguments[0] not in {"build", "test", "run", "query", "cquery", "aquery", "mod", "info", "clean", "version", "help"}:
        parser.error("unsupported offline Bazel command")

    forbidden = ("--remote_", "--remote-", "--experimental_remote_", "--override_repository",
                 "--override_module", "--repo_env", "--action_env", "--host_action_env",
                 "--spawn_strategy", "--strategy", "--modify_execution_info")
    if any(argument.startswith(forbidden) for argument in arguments):
        parser.error("toolchain/environment overrides and remote services are not supported")

    output_base = options.output_base.resolve()
    output_base.mkdir(parents=True, exist_ok=True)
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

    if arguments[0] in {"build", "test", "run", "cquery", "aquery"}:
        policy.extend([
            "--incompatible_strict_action_env", "--stamp=false", "--spawn_strategy=sandboxed",
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
        config["bazel"], "--batch", f"--output_base={output_base}",
        f"--output_user_root={output_base / 'user'}",
        f"--server_javabase={config['jdk']}",
        "--host_jvm_args=-Dfile.encoding=UTF-8",
        "--nosystem_rc", "--nohome_rc", "--noworkspace_rc",
    ] + arguments
    try:
        status = subprocess.call(command, cwd=workspace, env=environment)
    finally:
        output_lock.close()
    raise SystemExit(status)


if __name__ == "__main__":
    main()

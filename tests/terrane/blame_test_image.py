"""Retains genuine Cargo graph-audit artifacts without running native tests.

Cargo runner discovery executes only libtest --list. The actual CLI's discovery
is intercepted before execution. Guest binding restores its original compiled
absolute pathname, so the unchanged integration tests invoke the retained CLI.
"""

import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import sys
import tomllib


TARGETS = {
    "sdk": ("terrane-sdk", "terrane/sdk/terrane-sdk", "entry_blame", "test"),
    "cli-tests": ("terrane-cli", "terrane/cli/terrane-cli", "local_cli", "test"),
    "cli": ("terrane-cli", "terrane/cli/terrane-cli", "terrane", "bin"),
}
SDK_FEATURES = ["send", "std", "surface-sdk", "tokio"]


def require(condition, message):
    """Refuses an unproven source, executable or process boundary."""
    if not condition:
        raise SystemExit(message)


def helpers(source):
    """Loads the existing source-bound ELF and complete-image helpers."""
    configured = runpy.run_path(str(source / "tests/terrane/configured_sdk_proof.py"))
    native = configured["native_helper"](source / "tests/terrane/native_sdk_test_image.py")
    return configured, native


def capture(arguments):
    """Records the real Cargo launch and executes only test inventory discovery."""
    destination, executable, name, *command = arguments
    require(command == [executable, "--list" if name != "cli" else "--discover"],
            "unexpected blame discovery command")
    Path(destination).write_text(json.dumps({
        "argv": command, "cwd": os.getcwd(), "library_path": os.environ.get("LD_LIBRARY_PATH"),
    }, indent=2) + "\n")
    if name != "cli":
        os.execve(executable, command, dict(os.environ))


def cargo_flags(name):
    """Preserves each original gate's package and feature selection."""
    package, _, target, kind = TARGETS[name]
    flags = ["--frozen", "--offline", "-p", package]
    if name == "sdk":
        flags += ["--features", "tokio,surface-sdk"]
    return flags + (["--test", target] if kind == "test" else ["--profile", "test", "--bin", target])


def select(events, packages, workspace, target_dir, name):
    """Requires exact Cargo package, target, source, feature and test-profile identity."""
    package, package_path, target, kind = TARGETS[name]
    matches = [item for item in packages
               if Path(item["manifest_path"]) == workspace / package_path / "Cargo.toml"]
    require(len(matches) == 1 and matches[0]["name"] == package, "ambiguous blame package")
    matches = [item for item in events if item.get("reason") == "compiler-artifact"
               and item.get("package_id") == matches[0]["id"]
               and item.get("target", {}).get("name") == target
               and item.get("target", {}).get("kind") == [kind]
               and item.get("executable")]
    require(len(matches) == 1, f"ambiguous blame artifact: {name}")
    artifact = matches[0]
    executable = Path(artifact["executable"])
    profile = artifact["profile"]
    source_path = "src/main.rs" if kind == "bin" else f"tests/{target}.rs"
    require(Path(artifact["target"]["src_path"]) == workspace / package_path / source_path
            and sorted(artifact["features"]) == (SDK_FEATURES if name == "sdk" else [])
            and profile["test"] is (kind == "test")
            and profile["opt_level"] == "s" and profile["debuginfo"] == 0
            and profile["debug_assertions"] is True and profile["overflow_checks"] is True
            and executable.is_file() and os.access(executable, os.X_OK)
            and executable.resolve().is_relative_to(target_dir.resolve()),
            f"blame source/feature/profile/executable mismatch: {name}")
    sdk = [item for item in packages if item["name"] == "terrane-sdk"]
    require(len(sdk) == 1, "ambiguous SDK dependency")
    dependencies = [item for item in events if item.get("reason") == "compiler-artifact"
                    and item.get("package_id") == sdk[0]["id"]
                    and item.get("target", {}).get("kind") == ["lib"]]
    require(dependencies and all(sorted(item["features"]) == SDK_FEATURES for item in dependencies),
            "blame artifact SDK dependency profile mismatch")
    return artifact, executable, dependencies


def discover(name, executable, workspace, target_dir, target_libraries, temporary, native):
    """Captures the original loader directories and package working directory."""
    launch_path = temporary / f"blame-{name}-launch.json"
    runner = temporary / f"blame-{name}-runner"
    python = Path(shutil.which("python3") or "").resolve()
    require(python.is_file() and python.is_relative_to("/nix/store"), "untrusted discovery Python")
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
        "exec " + " ".join(shlex.quote(str(value)) for value in [
            python, Path(__file__).resolve(), "capture", launch_path, executable, name,
        ]) + ' "$@"', "",
    ]))
    runner.chmod(0o755)
    triple = target_libraries.parent.name.upper().replace("-", "_")
    environment = dict(os.environ)
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    command = ["cargo", "run" if name == "cli" else "test", *cargo_flags(name),
               "--", "--discover" if name == "cli" else "--list"]
    before = native.source_hashes(workspace, Path(os.environ["src"]))
    with (temporary / f"blame-{name}-discovery.log").open("w") as log:
        subprocess.run(command, env=environment, check=True, stdout=log, stderr=subprocess.STDOUT)
    require(before == native.source_hashes(workspace, Path(os.environ["src"])),
            "blame discovery changed immutable inputs")
    launch = json.loads(launch_path.read_text())
    expected_cwd = workspace if name == "cli" else workspace / TARGETS[name][1]
    require(launch["cwd"] == str(expected_cwd) and launch["library_path"]
            and all(launch["library_path"].split(":")), "unexpected blame launch environment")
    directories = [native.allowed_directory(value, target_dir)
                   for value in launch["library_path"].split(":")]
    require(all(path.is_dir() for path in directories), "absent blame runtime directory")
    return launch, directories


def verify(image, source, completed=True):
    """Checks every retained byte, immutable crate input and external runtime."""
    configured, native = helpers(source)
    identity = json.loads((image / "share/identity.json").read_text())
    require(identity["schema_version"] == 1 and identity["source"] == str(source)
            and set(identity["artifacts"]) == set(TARGETS)
            and identity["input_sha256"] == native.source_hashes(source / "crates", source),
            "blame image source or target mismatch")
    require(json.loads((image / "share/checksums.json").read_text()) == configured["file_manifest"](image),
            "blame image payload changed")
    marker = image / configured["PLATFORM_MARKER"]
    require((not completed and not marker.exists()) or marker.read_bytes() == b"x86_64-linux\n",
            "blame platform marker mismatch")
    for name, artifact in identity["artifacts"].items():
        require(configured["digest"](image / "libexec" / name) == artifact["binary_sha256"],
                "blame retained executable changed")
        for path, expected in artifact["external_runtime_sha256"].items():
            require(configured["digest"](Path(path)) == expected, "blame external runtime changed")
    return identity


def install():
    """Publishes the two tests and their actual CLI with separate loader closures."""
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    temporary, output, target_dir = (Path(os.environ[name]) for name in ["TMPDIR", "out", "CARGO_TARGET_DIR"])
    require(target_dir.is_absolute() and target_dir.is_relative_to("/build"),
            "blame guest requires a private /build Cargo target")
    configured, native = helpers(source)
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"},
            "unreviewed blame workspace test profile")
    packages = json.loads((temporary / "blame-packages.json").read_text())["packages"]
    target_libraries = Path((temporary / "blame-target-libdir.txt").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.is_relative_to("/nix/store")
            and target_libraries.parent.name == "x86_64-unknown-linux-gnu", "untrusted Rust target libraries")
    hashes = native.source_hashes(workspace, source)
    for directory in ["bin", "libexec", "lib", "share"]:
        (output / directory).mkdir()
    identity = {"schema_version": 1, "source": str(source), "input_sha256": hashes,
                "cargo_target_dir": str(target_dir), "artifacts": {}}
    for name in TARGETS:
        log = temporary / ("blame-sdk-build.jsonl" if name == "sdk" else "blame-cli-build.jsonl")
        artifact, executable, dependencies = select(configured["records"](log), packages, workspace, target_dir, name)
        binary_hash = configured["digest"](executable)
        launch, directories = discover(name, executable, workspace, target_dir, target_libraries, temporary, native)
        require(configured["digest"](executable) == binary_hash, "Cargo discovery rebuilt the blame executable")
        libraries, store_dirs = native.runtime_closure(executable, directories, target_dir)
        shutil.copy2(executable, output / "libexec" / name)
        library_directory = output / "lib" / name
        library_directory.mkdir()
        for filename, path in libraries.items():
            shutil.copy2(path, library_directory / filename)
        library_path = ":".join(map(str, [library_directory, *store_dirs]))
        external = configured["external_runtime"](executable, directories, target_dir, native)
        shell = Path(os.environ["CONFIG_SHELL"])
        external[str(shell)] = configured["digest"](shell)
        external.update(configured["external_runtime"](shell, directories, target_dir, native))
        working_directory = Path(launch["cwd"]).relative_to(workspace).as_posix()
        wrapper = output / "bin" / name
        wrapper.write_text("\n".join([
            f"#!{shell}", "set -eu",
            '[ "${src:-}" = ' + shlex.quote(str(source)) + " ]",
            "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
            "cd -- " + shlex.quote(str(source / "crates" / working_directory)),
            "exec " + shlex.quote(str(output / "libexec" / name)) + ' "$@"', "",
        ]))
        wrapper.chmod(0o755)
        identity["artifacts"][name] = {
            "artifact": artifact, "repository_compiler_events": dependencies,
            "original_executable": str(executable), "binary_sha256": binary_hash,
            "working_directory": working_directory, "runtime_library_path": library_path,
            "external_runtime_sha256": external,
        }
        for path in [temporary / f"blame-{name}-launch.json", temporary / f"blame-{name}-runner",
                     temporary / f"blame-{name}-discovery.log"]:
            shutil.copy2(path, output / "share" / path.name)
    require(hashes == native.source_hashes(workspace, source), "blame image changed source inputs")
    for path in [temporary / "blame-sdk-build.jsonl", temporary / "blame-cli-build.jsonl",
                 temporary / "blame-packages.json"]:
        shutil.copy2(path, output / "share" / path.name)
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/checksums.json").write_text(json.dumps(configured["file_manifest"](output), indent=2) + "\n")
    verify(output, source, completed=False)


def bind_cli(image, source):
    """Restores only the original Cargo executable pathname in a fresh guest."""
    require(os.getuid() == os.geteuid() == 0, "CLI guest binding requires guest root")
    identity = verify(image, source)
    target = Path(identity["cargo_target_dir"])
    executable = Path(identity["artifacts"]["cli"]["original_executable"])
    require(target.is_absolute() and target.is_relative_to("/build")
            and executable.is_relative_to(target) and executable.name == "terrane"
            and ".." not in executable.parts and not executable.exists() and not executable.is_symlink(),
            "unsafe original CLI guest pathname")
    # Only a root-owned symlink is created. Executable and runtime bytes remain
    # in the immutable store; no test or CLI assertion receives a path override.
    current = Path("/")
    for component in executable.parent.parts[1:]:
        current /= component
        if not current.exists():
            current.mkdir(mode=0o755)
            current.chmod(0o755)
        require(not current.is_symlink() and current.is_dir()
                and current.stat().st_uid == 0 and current.stat().st_mode & 0o022 == 0,
                "unprotected CLI guest ancestor")
    executable.symlink_to(image / "bin/cli")


def main():
    """Separates compilation discovery, immutable verification and guest binding."""
    sys.dont_write_bytecode = True
    command, *arguments = sys.argv[1:]
    if command == "install" and not arguments:
        install()
    elif command == "capture":
        capture(arguments)
    elif command == "bind-cli" and len(arguments) == 2:
        bind_cli(*map(Path, arguments))
    elif command == "verify" and len(arguments) == 2:
        verify(*map(Path, arguments))
    else:
        raise SystemExit("unexpected blame image arguments")


if __name__ == "__main__":
    main()

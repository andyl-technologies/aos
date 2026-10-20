"""Binds configured SDK artifacts, launch bytes and independent proof consumers.

Installation executes only Cargo discovery and libtest inventory. Ordinary unit
qualification executes the named pure/token-file tests. Irreversible startup is
available only through the explicit example launcher in a fresh guest actor.
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tomllib


CASES = [
    "preflight_refuses_unavailable_compositions_before_missing_authority_io",
    "preflight_refuses_roles_and_missing_trust_without_installation",
    "role_selection_and_instance_credentials_fail_before_any_repository_open",
    "encoded_bucket_traversal_is_rejected_without_path_normalization",
    "pure_sdk_profile_matches_the_actual_compiled_registry",
    "complete_exposure_list_rejects_late_unsupported_credentials_without_effects",
    "preflight_rejects_endpoints_overlapping_repository_state",
    "credential_references_have_no_provider_or_path_normalization_fallback",
    "native_token_reads_are_regular_nofollow_and_bounded",
    "fifo_and_device_credentials_are_classified_before_any_read",
    "failure_display_debug_and_entire_source_chain_redact_private_data",
]
PREFIX = "configured_sdk::tests::"
FLAGS = ["--frozen", "--offline", "-p", "terrane-linux",
         "--features", "tokio,terrane/surface-sdk"]
FS_FEATURES = ["tokio"]
REPOSITORY_FEATURES = ["send", "std", "surface-sdk", "tokio"]


def require(condition, message):
    """Refuses an unproven identity or result."""
    if not condition:
        raise SystemExit(message)


def digest(path):
    """Hashes the actual file bytes without canonicalizing their contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_helper(path):
    """Loads the source-bound common ELF/source helper without editing it."""
    spec = importlib.util.spec_from_file_location("configured_native_image", path)
    require(spec is not None and spec.loader is not None, "missing native image helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def records(path):
    """Reads real Cargo JSON compiler events."""
    return [json.loads(line) for line in path.read_text().splitlines()]


def select_artifact(events, packages, workspace, target, kind):
    """Checks both the FS target and its actually compiled SDK dependency."""
    package = [item for item in packages
               if pathlib.Path(item["manifest_path"]) == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
    repository = [item for item in packages
                  if pathlib.Path(item["manifest_path"]) == workspace / "terrane/sdk/terrane-sdk/Cargo.toml"]
    require(len(package) == len(repository) == 1, "ambiguous source packages")
    name = "terrane_linux" if kind == "unit" else "configured_sdk_fixture"
    candidates = [event for event in events if event.get("reason") == "compiler-artifact"
                  and event.get("target", {}).get("name") == name
                  and event.get("executable")]
    require(len(candidates) == 1, "ambiguous configured SDK artifact")
    artifact = candidates[0]
    source = "terrane/linux/terrane-linux/src/lib.rs" if kind == "unit" else "terrane/linux/terrane-linux/examples/configured_sdk_fixture.rs"
    profile = artifact["profile"]
    executable = pathlib.Path(artifact["executable"])
    test = kind == "unit"
    require(package[0]["name"] == "terrane-linux"
            and artifact["package_id"] == package[0]["id"]
            and artifact["target"]["kind"] == (["lib"] if test else ["example"])
            and pathlib.Path(artifact["target"]["src_path"]) == workspace / source
            and sorted(artifact["features"]) == FS_FEATURES
            and profile["test"] is test and profile["debug_assertions"] is True
            and profile["overflow_checks"] is True
            and profile["opt_level"] == ("s" if test else "0")
            and profile["debuginfo"] == (0 if test else 2)
            and executable.is_file() and os.access(executable, os.X_OK)
            and executable.resolve().is_relative_to(target.resolve()),
            "configured SDK target/source/profile mismatch")
    dependency = [event for event in events
                  if event.get("reason") == "compiler-artifact"
                  and event.get("package_id") == repository[0]["id"]
                  and event.get("target", {}).get("kind") == ["lib"]]
    require(dependency and all(sorted(event["features"]) == REPOSITORY_FEATURES
                               for event in dependency),
            "actual compiled terrane dependency lacks the exact SDK feature profile")
    return artifact, executable, dependency


def capture(arguments):
    """Captures the actual Cargo runner environment without starting an example."""
    destination, expected, kind, *command = arguments
    require(command and command[0] == expected, "Cargo runner executable mismatch")
    require(command[1:] == (["--list"] if kind == "unit" else ["--discover"]),
            "unexpected Cargo discovery arguments")
    pathlib.Path(destination).write_text(json.dumps({
        "argv": command, "cwd": os.getcwd(), "environment": dict(os.environ),
    }, indent=2) + "\n")
    if kind == "unit":
        os.execve(expected, command, dict(os.environ))


def discover(artifact, executable, kind, workspace, target, temporary, target_libraries, native):
    """Discovers each genuine launch while retaining source and artifact identity."""
    capture_path = temporary / f"configured-sdk-{kind}-launch.json"
    runner = temporary / f"configured-sdk-{kind}-runner"
    python = pathlib.Path(shutil.which("python3") or "").resolve()
    require(python.is_file() and python.is_relative_to("/nix/store"), "untrusted Python runner")
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
        "exec " + " ".join(shlex.quote(str(part)) for part in [
            python, pathlib.Path(__file__).resolve(), "capture", capture_path,
            executable, kind]) + ' "$@"', "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_libraries.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    command = (["cargo", "test", *FLAGS, "--lib", "--", "--list"] if kind == "unit"
               else ["cargo", "run", *FLAGS, "--example", "configured_sdk_fixture", "--", "--discover"])
    before = digest(executable)
    with (temporary / f"configured-sdk-{kind}-discovery.log").open("w") as log:
        subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    require(digest(executable) == before, "Cargo discovery changed the selected executable")
    launch = json.loads(capture_path.read_text())
    expected_cwd = workspace / "terrane/linux/terrane-linux" if kind == "unit" else workspace
    require(launch["cwd"] == str(expected_cwd), "unexpected Cargo launch working directory")
    library_path = launch["environment"].get("LD_LIBRARY_PATH", "")
    require(library_path and all(library_path.split(":")), "missing Cargo loader environment")
    directories = [native.allowed_directory(value, target) for value in library_path.split(":")]
    require(all(path.is_dir() for path in directories), "absent Cargo loader directory")
    libraries, store_directories = native.runtime_closure(executable, directories, target)
    return launch, libraries, store_directories, python


def inventory(binary, environment, cwd):
    """Verifies the complete configured SDK inventory against actual libtest."""
    result = subprocess.run([str(binary), "--list"], env=environment, cwd=cwd,
                            capture_output=True, text=True, check=True)
    listed = [line.removesuffix(": test") for line in result.stdout.splitlines()
              if line.startswith(PREFIX) and line.endswith(": test")]
    expected = [PREFIX + case for case in CASES]
    require(len(listed) == 11 and sorted(listed) == sorted(expected),
            "actual configured SDK test inventory differs from the eleven required cases")
    return result.stdout


def external_runtime(executable, directories, target, native):
    """Hashes only the reachable immutable ELF libraries and interpreter."""
    headers = subprocess.run(["readelf", "--program-headers", str(executable)],
                             capture_output=True, text=True, check=True).stdout
    retained = {}
    for value in re.findall(r"Requesting program interpreter: ([^\]]+)", headers):
        path = pathlib.Path(value)
        require(path.resolve().is_relative_to("/nix/store"), "untrusted ELF interpreter")
        retained[str(path)] = digest(path)
    pending = [(executable, [])]
    loaded = set()
    while pending:
        binary, ancestors = pending.pop(0)
        needed, rpaths, runpath = native.elf_dependencies(binary, target)
        inherited = ([] if runpath else rpaths) + ancestors
        search = directories + rpaths if runpath else inherited + directories
        for name in needed:
            if name in loaded:
                continue
            candidates = [directory / name for directory in search if (directory / name).is_file()]
            require(candidates, "unresolved immutable runtime dependency")
            path = candidates[0]
            loaded.add(name)
            if path.resolve().is_relative_to("/nix/store"):
                retained[str(path)] = digest(path)
            else:
                require(path.resolve().is_relative_to(target.resolve()), "runtime outside allowed roots")
            pending.append((path, inherited))
    return retained


def file_manifest(image):
    """Includes every retained file except the manifest's own recursive hash."""
    return {path.relative_to(image).as_posix(): digest(path)
            for path in sorted(image.rglob("*"))
            if path.is_file() and path != image / "share/checksums.json"}


def verify(image, source):
    """Checks all final launch/runtime/identity bytes before any consumer effects."""
    manifest = json.loads((image / "share/checksums.json").read_text())
    require(manifest == file_manifest(image), "configured SDK image byte manifest mismatch")
    identity = json.loads((image / "share/identity.json").read_text())
    require(identity["schema_version"] == 1 and identity["source"] == str(source)
            and identity["cases"] == [PREFIX + case for case in CASES]
            and identity["requested_features"] == ["tokio", "terrane/surface-sdk"],
            "configured SDK image source/feature/inventory mismatch")
    for name, expected in identity["input_sha256"].items():
        require(digest(source / "crates" / name) == expected,
                "configured SDK immutable crate input mismatch")
    for name in ["unit", "example"]:
        item = identity["artifacts"][name]
        require(item["binary_sha256"] == digest(image / "libexec" / name)
                and item["features"] == FS_FEATURES
                and all(event["features"] == REPOSITORY_FEATURES
                        for event in item["repository_compiler_events"]),
                "configured SDK retained artifact mismatch")
        for path, expected in item["external_runtime_sha256"].items():
            require(digest(pathlib.Path(path)) == expected, "external runtime byte mismatch")
    return identity


def install(helper_path):
    """Publishes source-bound artifacts without executing irreversible startup."""
    native = native_helper(helper_path)
    workspace = pathlib.Path.cwd()
    source = pathlib.Path(os.environ["src"])
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    output = pathlib.Path(os.environ["out"])
    packages = json.loads((temporary / "configured-sdk-packages.json").read_text())["packages"]
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(manifest.get("profile", {}).get("dev", {}) == {}
            and manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"},
            "unreviewed workspace profile override")
    hashes = native.source_hashes(workspace, source)
    target_libraries = pathlib.Path((temporary / "configured-sdk-target-libdir").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.resolve().is_relative_to("/nix/store"),
            "untrusted Rust runtime location")
    for name in ["bin", "libexec", "share", "lib"]:
        (output / name).mkdir()
    shutil.copy2(__file__, output / "share/configured_sdk_proof.py")
    shutil.copy2(helper_path, output / "share/native_sdk_test_image.py")
    identity = {"schema_version": 1, "source": str(source), "input_sha256": hashes,
                "cases": [PREFIX + case for case in CASES],
                "requested_features": ["tokio", "terrane/surface-sdk"], "artifacts": {}}
    for kind in ["unit", "example"]:
        event_path = temporary / f"configured-sdk-{kind}.jsonl"
        artifact, executable, dependencies = select_artifact(
            records(event_path), packages, workspace, target, kind)
        launch, libraries, store_dirs, python = discover(
            artifact, executable, kind, workspace, target, temporary, target_libraries, native)
        destination = output / "libexec" / kind
        shutil.copy2(executable, destination)
        library_directory = output / "lib" / kind
        library_directory.mkdir()
        for name, path in libraries.items():
            shutil.copy2(path, library_directory / name)
        library_path = ":".join(map(str, [library_directory, *store_dirs]))
        shell = pathlib.Path(os.environ["CONFIG_SHELL"])
        directories = [native.allowed_directory(value, target) for value in
                       launch["environment"]["LD_LIBRARY_PATH"].split(":")]
        external = external_runtime(executable, directories, target, native)
        # The launcher also executes the declared AOS shell and Python verifier.
        # Their reachable ELF bytes are part of the same launch identity.
        for helper in [python, shell]:
            external[str(helper)] = digest(helper)
            external.update(external_runtime(helper, directories, target, native))
        working_directory = pathlib.Path(launch["cwd"]).relative_to(workspace).as_posix()
        identity["artifacts"][kind] = {
            "package_id": artifact["package_id"], "target": artifact["target"],
            "profile": artifact["profile"], "cargo_profile": "test" if kind == "unit" else "dev",
            "features": sorted(artifact["features"]), "repository_compiler_events": dependencies,
            "binary_sha256": digest(executable), "runtime_library_path": library_path,
            "external_runtime_sha256": external, "working_directory": working_directory,
        }
        wrapper = output / "bin" / f"configured-sdk-{kind}"
        wrapper.write_text("\n".join([
            f'#!{shell}', "set -eu",
            "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
            "exec " + " ".join(shlex.quote(str(part)) for part in [
                python, output / "share/configured_sdk_proof.py", "launch", output, kind]) + ' "$@"', "",
        ]))
        wrapper.chmod(0o755)
        for path in [event_path, temporary / f"configured-sdk-{kind}-launch.json",
                     temporary / f"configured-sdk-{kind}-runner",
                     temporary / f"configured-sdk-{kind}-discovery.log"]:
            shutil.copy2(path, output / "share" / path.name)
        if kind == "unit":
            environment = dict(os.environ, LD_LIBRARY_PATH=library_path)
            listing = inventory(destination, environment, workspace / "terrane/linux/terrane-linux")
            (output / "share/unit-inventory.txt").write_text(listing)
    require(hashes == native.source_hashes(workspace, source), "discovery changed crate inputs")
    shutil.copy2(temporary / "configured-sdk-packages.json", output / "share/packages.json")
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/checksums.json").write_text(json.dumps(file_manifest(output), indent=2) + "\n")
    verify(output, source)


def launch(image, kind, arguments):
    """Verifies the final image before replacing this process with its artifact."""
    identity = json.loads((image / "share/identity.json").read_text())
    verify(image, pathlib.Path(identity["source"]))
    require(kind in ["unit", "example"], "unknown configured SDK launcher")
    if kind == "example":
        status = dict(line.split(":", 1) for line in
                      pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
        require(os.getuid() == os.geteuid() == 840 and os.getgid() == os.getegid() == 840
                and os.getgroups() == [] and status["NoNewPrivs"].strip() == "1"
                and all(int(status[name].strip(), 16) == 0
                        for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
                "configured SDK guest actor lacks the explicit empty-capability identity")
    artifact = identity["artifacts"][kind]
    environment = dict(os.environ, LD_LIBRARY_PATH=artifact["runtime_library_path"])
    os.chdir(pathlib.Path(identity["source"]) / "crates" / artifact["working_directory"])
    executable = image / "libexec" / kind
    os.execve(executable, [str(executable), *arguments], environment)


def unit(image, source):
    """Runs all and only the eleven genuine configured SDK cases independently."""
    identity = verify(image, source)
    native = native_helper(image / "share/native_sdk_test_image.py")
    require(identity["input_sha256"] == native.source_hashes(pathlib.Path.cwd(), source),
            "unit consumer source differs from compiled source")
    wrapper = image / "bin/configured-sdk-unit"
    listing = inventory(wrapper, dict(os.environ), pathlib.Path.cwd())
    output = pathlib.Path(os.environ["out"])
    (output / "inventory.txt").write_text(listing)
    for case in CASES:
        name = PREFIX + case
        result = subprocess.run([str(wrapper), name, "--exact", "--nocapture"],
                                capture_output=True, text=True, check=True)
        require(f"test {name} ... ok" in result.stdout
                and "test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                "required configured SDK case did not execute and pass exactly once")
        (output / f"{case}.log").write_text(result.stdout + result.stderr)
    verify(image, source)


def main():
    """Selects discovery, verified launch or independent proof qualification."""
    command, *arguments = sys.argv[1:]
    if command == "capture":
        capture(arguments)
    elif command == "install":
        install(pathlib.Path(arguments[0]))
    elif command == "verify":
        verify(pathlib.Path(arguments[0]), pathlib.Path(arguments[1]))
    elif command == "launch":
        launch(pathlib.Path(arguments[0]), arguments[1], arguments[2:])
    elif command == "unit":
        unit(pathlib.Path(arguments[0]), pathlib.Path(arguments[1]))
    else:
        raise SystemExit("unknown configured SDK proof mode")


if __name__ == "__main__":
    main()

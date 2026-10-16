"""Installs exact source-bound native cache component executables and ELF closure."""

import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import native_sdk_test_image as shared

TARGETS = {
    "host_cache_fixture": ("terrane-fs", "example", "examples/host_cache_fixture.rs", ["native-test-fixtures", "tokio"]),
    "terrane": ("terrane-cli", "bin", "src/main.rs", []),
    "aos-terrane-host": ("aos-terrane", "bin", "src/bin/aos-terrane-host.rs", []),
}
PROFILE = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
           "overflow_checks": True, "test": False}


def digest(path):
    """Hashes the exact retained bytes, without invoking an ELF rewriter."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flags(name):
    """Selects the exact package and explicitly enabled fixture features."""
    package, kind, _, features = TARGETS[name]
    result = ["--frozen", "--offline", "-p", package]
    if features:
        result += ["--features", "native-test-fixtures"]
    return result + ["--example" if kind == "example" else "--bin", name]


def selected_artifacts(workspace, temporary, target):
    """Binds real Cargo package/target/profile/features to each executable."""
    packages = json.loads((temporary / "host-cache-packages.json").read_text())["packages"]
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    shared.require(manifest.get("profile", {}).get("dev", {}) == {}, "unreviewed cache proof development profile")
    result = {}
    for name, (crate, kind, source, features) in TARGETS.items():
        records = [json.loads(line) for line in (temporary / f"host-cache-{name}.jsonl").read_text().splitlines()]
        package = [item for item in packages if pathlib.Path(item["manifest_path"]) == workspace / crate / "Cargo.toml"]
        candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                      and item.get("target", {}).get("name") == name and item.get("executable")]
        shared.require(len(package) == len(candidates) == 1, f"ambiguous cache proof artifact: {name}")
        artifact = candidates[0]
        targets = [item for item in package[0]["targets"] if item["name"] == name and item["kind"] == [kind]]
        executable = pathlib.Path(artifact["executable"])
        shared.require(len(targets) == 1 and artifact["target"] == targets[0]
                       and artifact["package_id"] == package[0]["id"] and package[0]["name"] == crate
                       and artifact["target"]["crate_types"] == ["bin"]
                       and pathlib.Path(artifact["target"]["src_path"]) == workspace / crate / source
                       and artifact["profile"] == PROFILE and sorted(artifact["features"]) == features
                       and str(executable) in artifact["filenames"]
                       and executable.is_file() and os.access(executable, os.X_OK)
                       and executable.resolve().is_relative_to(target.resolve()),
                       f"cache proof source/target/profile/features mismatch: {name}")
        shared.require(executable.read_bytes().startswith(b"\x7fELF"), f"non-ELF artifact: {name}")
        result[name] = (artifact, executable, digest(executable))
    return result


def cargo_directories(name, executable, temporary, target, workspace):
    """Captures a genuine Cargo launch without executing any role entry point."""
    target_lib = pathlib.Path((temporary / "host-cache-target-libdir").read_text().strip())
    shared.require(target_lib.is_dir() and target_lib.resolve().is_relative_to("/nix/store"), "untrusted target library directory")
    capture = temporary / f"host-cache-{name}-library-path"
    working = temporary / f"host-cache-{name}-working-directory"
    runner = temporary / f"host-cache-{name}-runner"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --discover ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(working)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_lib.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    with (temporary / f"host-cache-{name}-discovery.log").open("w") as log:
        subprocess.run(["cargo", "run", *flags(name), "--", "--discover"], env=environment,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    text = capture.read_text()
    shared.require(text.endswith("\n") and text.count("\n") == 1 and text.strip(), "missing Cargo launch environment")
    shared.require(working.read_text() == str(workspace) + "\n", "Cargo launch working-directory mismatch")
    directories = [shared.allowed_directory(value, target) for value in text[:-1].split(":")]
    shared.require(all(path.is_dir() for path in directories), "missing Cargo runtime library directory")
    return directories


def main():
    """Publishes immutable artifacts without claiming native execution."""
    workspace = pathlib.Path.cwd()
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    source = pathlib.Path(os.environ["src"])
    output = pathlib.Path(os.environ["out"])
    # Nix file inputs have hash-prefixed store basenames. Their repository
    # identities are explicit; neither a basename guess nor a fallback may bind
    # the executed installer to another immutable source file.
    for path, name in [
        (pathlib.Path(__file__), "host_cache_image.py"),
        (pathlib.Path(shared.__file__), "native_sdk_test_image.py"),
    ]:
        relative = "tests/terrane/" + name
        shared.require(path.read_bytes() == (source / relative).read_bytes(), "executed proof helper differs from source")
    artifacts = selected_artifacts(workspace, temporary, target)
    source_hashes = shared.source_hashes(workspace, source)
    for name in ["host-cache-proof.nix", "host_cache_image.py", "host_cache_vm.py", "native_sdk_test_image.py"]:
        path = source / "tests/terrane" / name
        shared.require(path.read_bytes() == (workspace.parent / "tests/terrane" / name).read_bytes(), "mutable proof input: " + name)
        source_hashes["tests/terrane/" + name] = digest(path)
    libraries = {}
    store_paths = []
    for name, (artifact, executable, original_hash) in artifacts.items():
        directories = cargo_directories(name, executable, temporary, target, workspace)
        shared.require(digest(executable) == original_hash, "Cargo discovery changed selected ELF")
        reachable, stores = shared.runtime_closure(executable, directories, target)
        for library, path in reachable.items():
            shared.require(library not in libraries or libraries[library].read_bytes() == path.read_bytes(), "ambiguous cache proof runtime: " + library)
            libraries[library] = path
        for path in stores:
            if path not in store_paths:
                store_paths.append(path)
    for name in ["bin", "lib", "share"]:
        (output / name).mkdir()
    checksums = []
    identities = {}
    for name, (artifact, executable, original_hash) in artifacts.items():
        installed = output / "bin" / name
        shutil.copy2(executable, installed)
        shared.require(digest(installed) == digest(executable) == original_hash, "installed ELF differs from Cargo artifact")
        identities[name] = {"cargo_artifact": artifact, "cargo_elf_sha256": original_hash,
                            "installed_elf_sha256": digest(installed), "installed_path": "bin/" + name}
        checksums.append(f"{original_hash}  bin/{name}\n")
        for suffix in ["jsonl", "discovery.log", "library-path", "working-directory"]:
            filename = f"host-cache-{name}.{suffix}" if suffix == "jsonl" else f"host-cache-{name}-{suffix}"
            shutil.copy2(temporary / filename, output / "share" / filename)
    for name, path in libraries.items():
        installed = output / "lib" / name
        shutil.copy2(path, installed)
        shared.require(digest(installed) == digest(path), "installed runtime changed: " + name)
        checksums.append(f"{digest(installed)}  lib/{name}\n")
    # Retain the actual guest entry point in the image closure, with the same
    # immutable-source binding as the executable artifacts.
    supervisor_source = source / "tests/terrane/host_cache_vm.py"
    supervisor = output / "share/host_cache_vm.py"
    shutil.copy2(supervisor_source, supervisor)
    shared.require(supervisor.read_bytes() == supervisor_source.read_bytes(), "installed supervisor differs from source")
    supervisor_identity = {"source_path": "tests/terrane/host_cache_vm.py",
                           "installed_path": "share/host_cache_vm.py", "sha256": digest(supervisor)}
    checksums.append(f"{digest(supervisor)}  share/host_cache_vm.py\n")

    library_path = ":".join(map(str, [output / "lib", *store_paths]))
    listed = subprocess.run([str(output / "bin/host_cache_fixture"), "--list"],
                            env=dict(os.environ, LD_LIBRARY_PATH=library_path), check=True,
                            text=True, capture_output=True).stdout.splitlines()
    expected = ["host-cache:" + name for name in ["prepare", "empty", "refuse", "cancel", "edquot", "hold", "start-refuse"]]
    shared.require(listed == expected, "cache fixture exact selector inventory mismatch")
    identity = {"schema_version": 1, "source": str(source), "artifacts": identities,
                "input_sha256": source_hashes, "selectors": listed, "supervisor": supervisor_identity,
                "runtime_library_path": library_path, "native_cases_executed": []}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/runtime-library-path").write_text(library_path + "\n")
    (output / "share/elf-sha256sum").write_text("".join(checksums))
    shutil.copy2(temporary / "host-cache-packages.json", output / "share/host-cache-packages.json")


if __name__ == "__main__":
    main()

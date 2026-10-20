"""Installs a source-bound native SDK test image without qualifying any tests.

Cargo discovery supplies the actual executable and launch environment. ELF
inspection retains only reachable runtime libraries, leaving compiler plugins
behind. Every gate must still discover and execute its own required cases.
Closed surface-SDK and default-Tokio variants retain their distinct original
feature selections; importing shared ELF helpers does not select a variant.
"""

from collections import deque

import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tomllib


FEATURES = ["send", "std", "surface-sdk", "tokio"]
CARGO_FLAGS = [
    "--frozen", "--offline", "-p", "terrane-sdk", "--no-default-features",
    "--features", "tokio,surface-sdk", "--lib",
]


def image_configuration(variant):
    """Selects one closed feature contract without changing imported helpers."""
    if variant == "surface-sdk":
        return {"default_features": False,
                "requested_features": ["tokio", "surface-sdk"],
                "features": FEATURES, "cargo_flags": CARGO_FLAGS}
    if variant == "default-tokio":
        return {"default_features": True, "requested_features": ["tokio"],
                "features": ["default", "send", "std", "tokio"],
                "cargo_flags": ["--frozen", "--offline", "-p", "terrane-sdk",
                                "--features", "tokio", "--lib"]}
    raise SystemExit(f"unknown native SDK test image variant: {variant}")


def require(condition, message):
    """Stops publication when an image invariant is not established."""
    if not condition:
        raise SystemExit(message)


def selected_artifact(workspace, target_dir, temporary, expected_features=None):
    """Binds exactly one real library-test artifact to its source and profile."""
    expected_features = FEATURES if expected_features is None else expected_features
    records = [json.loads(line) for line in
               (temporary / "native-sdk-build.jsonl").read_text().splitlines()]
    candidates = [record for record in records
                  if record.get("reason") == "compiler-artifact"
                  and record.get("target", {}).get("name") == "terrane_sdk"
                  and record.get("profile", {}).get("test") is True]
    require(len(candidates) == 1, "expected exactly one terrane library-test artifact")
    artifact = candidates[0]
    packages = json.loads((temporary / "native-sdk-packages.json").read_text())["packages"]
    selected = [item for item in packages
                if pathlib.Path(item["manifest_path"]) == workspace / "terrane/sdk/terrane-sdk/Cargo.toml"]
    require(len(selected) == 1 and artifact["package_id"] == selected[0]["id"],
            "native SDK artifact does not belong to the selected source package")

    profile = artifact["profile"]
    executable = pathlib.Path(artifact.get("executable") or "")
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(artifact["target"]["kind"] == ["lib"]
            and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/sdk/terrane-sdk/src/lib.rs"
            and sorted(artifact.get("features", [])) == expected_features
            and profile.get("opt_level") == "s" and profile.get("debuginfo") == 0
            and manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"}
            and selected[0]["name"] == "terrane-sdk"
            and executable.is_file() and os.access(executable, os.X_OK)
            and executable.resolve().is_relative_to(target_dir.resolve()),
            "native SDK source, feature, profile, or executable identity mismatch")
    return artifact, executable


def source_hashes(workspace, source):
    """Checks every immutable crate input, apart from generated vendor config."""
    hashes = {}
    for path in sorted((source / "crates").rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(source / "crates").as_posix()
        if name == ".cargo/config.toml":
            continue
        content = (workspace / name).read_bytes()
        require(content == path.read_bytes(), f"immutable SDK input changed: {name}")
        hashes[name] = hashlib.sha256(content).hexdigest()
    return hashes


def allowed_directory(value, target_dir):
    """Rejects library searches outside the target tree and immutable store."""
    path = pathlib.Path(value)
    require(path.is_absolute(), f"relative runtime library directory: {value}")
    resolved = path.resolve()
    require(resolved.is_relative_to(target_dir.resolve())
            or resolved.is_relative_to("/nix/store"),
            f"runtime library directory outside allowed roots: {value}")
    return path


def cargo_discovery(executable, target_dir, temporary, target_libraries, workspace,
                    cargo_flags=None):
    """Captures one genuine Cargo launch while executing only libtest --list."""
    cargo_flags = CARGO_FLAGS if cargo_flags is None else cargo_flags
    capture = temporary / "native-sdk-cargo-library-path.txt"
    cwd_capture = temporary / "native-sdk-cargo-working-directory.txt"
    runner = temporary / "native-sdk-discovery-runner"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}',
        "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable))
        + ' ] && [ "$2" = --list ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(cwd_capture)),
        'exec "$@"',
        "",
    ]))
    runner.chmod(0o755)
    environment = os.environ.copy()
    triple = target_libraries.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    with (temporary / "native-sdk-cargo-discovery.log").open("w") as log:
        subprocess.run(["cargo", "test", *cargo_flags, "--", "--list"],
                       env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    require(capture.is_file(), "Cargo discovery did not invoke the bound test runner")
    captured = capture.read_text()
    require(captured.endswith("\n") and captured.count("\n") == 1 and captured.strip(),
            "absent or malformed Cargo runtime library environment")
    directories = []
    for value in captured[:-1].split(":"):
        directory = allowed_directory(value, target_dir)
        require(directory.is_dir(), f"absent Cargo runtime library directory: {directory}")
        if directory not in directories:
            directories.append(directory)
    require(cwd_capture.is_file(), "Cargo discovery did not capture its working directory")
    captured_cwd = cwd_capture.read_text()
    require(captured_cwd.endswith("\n") and captured_cwd.count("\n") == 1,
            "malformed Cargo discovery working directory")
    working_directory = pathlib.Path(captured_cwd[:-1])
    require(working_directory.is_absolute()
            and working_directory == workspace / "terrane/sdk/terrane-sdk"
            and working_directory.resolve() == (workspace / "terrane/sdk/terrane-sdk").resolve(),
            "Cargo discovery did not run in the selected source package")
    return directories, working_directory.relative_to(workspace).as_posix()


def elf_dependencies(binary, target_dir):
    """Reads dynamic dependencies and loader paths with source-built readelf."""
    dynamic = subprocess.run(["readelf", "--dynamic", str(binary)],
                             capture_output=True, text=True, check=True).stdout
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    rpath = re.findall(r"\(RPATH\).*?\[([^\]]+)\]", dynamic)
    runpath = re.findall(r"\(RUNPATH\).*?\[([^\]]+)\]", dynamic)
    require(len(rpath) <= 1 and len(runpath) <= 1, f"ambiguous ELF search paths: {binary}")
    paths = []
    for value in (runpath or rpath):
        for directory in value.split(":"):
            expanded = directory.replace("${ORIGIN}", str(binary.parent))
            expanded = expanded.replace("$ORIGIN", str(binary.parent))
            require("$" not in expanded, f"unsupported ELF search substitution: {directory}")
            paths.append(allowed_directory(expanded, target_dir))
    return needed, paths, bool(runpath)


def runtime_closure(executable, directories, target_dir):
    """Resolves DT_NEEDED transitively without retaining unrelated plugins."""
    headers = subprocess.run(["readelf", "--program-headers", str(executable)],
                             capture_output=True, text=True, check=True).stdout
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", headers)
    require(len(interpreters) <= 1, "ambiguous executable interpreter")
    for value in interpreters:
        interpreter = pathlib.Path(value)
        require(interpreter.is_file() and interpreter.resolve().is_relative_to("/nix/store"),
                f"executable interpreter is not an immutable store input: {value}")
    pending = deque([(executable, [])])
    loaded = {}
    visited = set()
    copied = {}
    store_directories = [path for path in directories if path.resolve().is_relative_to("/nix/store")]
    while pending:
        binary, ancestor_rpaths = pending.popleft()
        if binary.resolve() in visited:
            continue
        visited.add(binary.resolve())
        needed, rpaths, has_runpath = elf_dependencies(binary, target_dir)
        # glibc elf/dl-load.c searches the loader's RPATH and each ancestor
        # before LD_LIBRARY_PATH, unless this loader has RUNPATH. RUNPATH
        # follows the environment and applies only to this loader's children.
        own_rpaths = [] if has_runpath else rpaths
        inherited = own_rpaths + ancestor_rpaths
        search = directories + rpaths if has_runpath else inherited + directories
        for directory in rpaths:
            if directory.resolve().is_relative_to("/nix/store") and directory not in store_directories:
                store_directories.append(directory)
        for name in needed:
            require("/" not in name, f"nonportable ELF dependency name: {name}")
            if name in loaded:
                continue
            candidates = [directory / name for directory in search if (directory / name).is_file()]
            require(candidates, f"unresolved runtime library {name} needed by {binary}")
            selected = candidates[0]
            # Ordered search paths are authoritative, just as in ld.so.
            # Ambiguity is refused only when installation would collapse two
            # genuinely selected files into the same destination name.
            resolved = selected.resolve()
            require(resolved.is_relative_to(target_dir.resolve())
                    or resolved.is_relative_to("/nix/store"), f"runtime library escapes allowed roots: {selected}")
            if resolved.is_relative_to(target_dir.resolve()):
                require(name not in copied or copied[name].read_bytes() == selected.read_bytes(),
                        f"ambiguous installed runtime library: {name}")
                copied[name] = selected
            loaded[name] = selected
            pending.append((selected, inherited))
    return copied, store_directories


def install_image(artifact, executable, source, output, hashes, libraries,
                  store_directories, working_directory, temporary, configuration=None):
    """Publishes immutable executable, runtime closure, and binding metadata."""
    if configuration is None:
        configuration = image_configuration("surface-sdk")
    for name in ["bin", "libexec", "lib", "share"]:
        (output / name).mkdir()
    comparison = shutil.which("cmp")
    require(comparison is not None, "declared AOS comparison tool is unavailable")
    comparison_tool = pathlib.Path(comparison).resolve()
    require(pathlib.Path(comparison).is_absolute()
            and comparison_tool.is_relative_to("/nix/store")
            and comparison_tool.is_file() and os.access(comparison_tool, os.X_OK),
            "comparison tool is not an immutable AOS store executable")
    quoted_comparison = shlex.quote(str(comparison_tool))
    installed = output / "libexec/terrane-native-sdk-tests"
    shutil.copy2(executable, installed)
    for name, library in libraries.items():
        shutil.copy2(library, output / "lib" / name)
    library_path = ":".join(map(str, [output / "lib", *store_directories]))
    wrapper = "\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
        'if [ "${src:-}" != ' + shlex.quote(str(source)) + ' ]; then',
        "  printf '%s\\n' 'native SDK test image source mismatch' >&2", "  exit 1", "fi",
        "export LD_LIBRARY_PATH=" + shlex.quote(library_path) + '"${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"',
        'workspace=$(pwd -P)',
        quoted_comparison + ' --silent "$workspace/Cargo.toml" "$src/crates/Cargo.toml"',
        quoted_comparison + ' --silent "$workspace/' + working_directory + '/Cargo.toml" '
        + '"$src/crates/' + working_directory + '/Cargo.toml"',
        'cd -P -- "$workspace/' + working_directory + '"',
        '[ "$(pwd -P)" = "$workspace/' + working_directory + '" ]',
        "exec " + shlex.quote(str(installed)) + ' "$@"', "",
    ])
    runner = output / "bin/terrane-native-sdk-tests"
    runner.write_text(wrapper)
    runner.chmod(0o755)
    identity = {"schema_version": 1, "source": str(source), "cargo_profile": "test",
                "default_features": configuration["default_features"],
                "requested_features": configuration["requested_features"],
                "features": configuration["features"], "profile": artifact["profile"],
                "package_id": artifact["package_id"], "input_sha256": hashes,
                "runtime_library_path": library_path,
                "working_directory": working_directory,
                "comparison_tool": str(comparison_tool),
                "copied_runtime_libraries": sorted(libraries)}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    for original, name in [("native-sdk-build.jsonl", "build.jsonl"),
                           ("native-sdk-cargo-discovery.log", "cargo-discovery.log"),
                           ("native-sdk-cargo-library-path.txt", "cargo-library-path.txt"),
                           ("native-sdk-cargo-working-directory.txt", "cargo-working-directory.txt")]:
        shutil.copy2(temporary / original, output / "share" / name)


def main():
    """Validates discovery and installs one native SDK test image."""
    require(len(sys.argv) in (1, 2), "expected at most one native SDK image variant")
    variant = sys.argv[1] if len(sys.argv) == 2 else "surface-sdk"
    configuration = image_configuration(variant)
    workspace = pathlib.Path.cwd()
    target_dir = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    output = pathlib.Path(os.environ["out"])
    temporary = pathlib.Path(os.environ["TMPDIR"])
    source = pathlib.Path(os.environ["src"])
    artifact, executable = selected_artifact(
        workspace, target_dir, temporary, configuration["features"])
    hashes = source_hashes(workspace, source)
    target_libraries = pathlib.Path((temporary / "native-sdk-target-libdir.txt").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.is_relative_to("/nix/store"),
            "Rust target libraries are not immutable store inputs")
    directories, working_directory = cargo_discovery(
        executable, target_dir, temporary, target_libraries, workspace,
        configuration["cargo_flags"])
    libraries, store_directories = runtime_closure(executable, directories, target_dir)
    require(hashes == source_hashes(workspace, source), "Cargo discovery changed source inputs")
    install_image(artifact, executable, source, output, hashes, libraries,
                  store_directories, working_directory, temporary, configuration)


if __name__ == "__main__":
    main()

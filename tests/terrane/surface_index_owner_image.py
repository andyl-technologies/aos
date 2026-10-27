"""Installs exact native surface-owner fixture bytes and their reachable ELF closure."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

from native_sdk_test_image import allowed_directory, require, runtime_closure, source_hashes


def digest(path):
    """Hashes the actual retained bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    """Binds a genuine Cargo launch to one immutable fixture and runtime closure."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    temporary = Path(os.environ["TMPDIR"])
    target = Path(os.environ["CARGO_TARGET_DIR"])
    inputs = source_hashes(workspace, source)
    rows = [json.loads(line) for line in (output / "surface-build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "surface_index_owner_fixture"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous structural surface-owner fixture artifact")
    artifact = artifacts[0]
    profile = artifact["profile"]
    require(artifact["target"]["kind"] == ["example"]
            and artifact["target"]["crate_types"] == ["bin"]
            and Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/examples/surface_index_owner_fixture.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/linux/terrane-linux") + "#")
            and artifact["features"] == ["native-test-fixtures", "surface-fuse", "tokio"]
            and not profile["test"] and profile["opt_level"] == "0"
            and profile["debuginfo"] == 2 and profile["debug_assertions"],
            "structural surface-owner fixture source, features or profile mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(target.resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid surface-owner ELF")
    original_digest = digest(executable)

    capture = output / "surface-cargo-library-path"
    working = output / "surface-cargo-working-directory"
    runner = temporary / "surface-owner-discovery-runner"
    runner.write_text("\n".join([
        "#!" + os.environ["CONFIG_SHELL"], "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --discover ]',
        'printf "%s\\n" "${LD_LIBRARY_PATH-}" > ' + shlex.quote(str(capture)),
        'pwd -P > ' + shlex.quote(str(working)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    target_libraries = Path((temporary / "structural-target-libdir").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.resolve().is_relative_to("/nix/store"),
            "surface-owner target libraries are not immutable")
    triple = target_libraries.parent.name.upper().replace("-", "_")
    environment = dict(os.environ)
    environment["CARGO_TARGET_" + triple + "_RUNNER"] = str(runner)
    with (output / "surface-cargo-discovery.log").open("w") as log:
        subprocess.run(["cargo", "run", "--frozen", "--offline", "-p", "terrane-linux",
                        "--no-default-features", "--features", "native-test-fixtures,surface-fuse",
                        "--example", "surface_index_owner_fixture", "--", "--discover"],
                       env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    text = capture.read_text()
    require(text.endswith("\n") and text.count("\n") == 1 and text.strip()
            and working.read_text() == str(workspace) + "\n", "invalid Cargo launch environment")
    directories = [allowed_directory(value, target) for value in text[:-1].split(":")]
    require(all(path.is_dir() for path in directories), "missing Cargo runtime directory")
    libraries, store_directories = runtime_closure(executable, directories, target)
    for name in ["bin", "libexec", "lib"]:
        (output / name).mkdir(exist_ok=True)
    installed = output / "libexec/surface-index-owner-fixture"
    shutil.copy2(executable, installed)
    for name, library in libraries.items():
        destination = output / "lib" / name
        require(not destination.exists() or digest(destination) == digest(library),
                "surface fixture runtime library collides with native image")
        shutil.copy2(library, destination)
    library_path = ":".join(map(str, [output / "lib", *store_directories]))
    wrapper = output / "bin/surface-index-owner-fixture"
    wrapper.write_text("\n".join([
        "#!" + os.environ["CONFIG_SHELL"], "set -eu",
        "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
        "exec " + shlex.quote(str(installed)) + ' "$@"', "",
    ]))
    wrapper.chmod(0o755)
    require(digest(executable) == original_digest == digest(installed), "fixture ELF changed during installation")
    require(source_hashes(workspace, source) == inputs, "surface-owner discovery changed source inputs")
    files = [installed, *sorted((output / "lib").iterdir())]
    (output / "surface-elf-sha256sum").write_text("".join(
        digest(path) + "  " + str(path.relative_to(output)) + "\n" for path in files))
    (output / "surface-identity.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact,
        "executable_sha256": original_digest, "runtime_library_path": library_path,
        "copied_runtime_libraries": sorted(libraries),
        "scope": "Native surface-index owner admission component; no worker or exposure authority",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

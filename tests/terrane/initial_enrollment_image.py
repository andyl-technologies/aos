"""Builds and independently checks an immutable initial-enrollment proof image.

Only the fixture's pure selector inventory may execute outside the VM. Cargo
events, source bytes, installed ELF, resolved runtime closure and both proof
scripts remain bound together; building this image executes no native case.
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

NAME = "initial_enrollment_fixture"
PACKAGE = "aos-terrane-integration"
PACKAGE_PATH = pathlib.Path("terrane/integration/aos-terrane-integration")
PROFILE = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
           "overflow_checks": True, "test": False}
SELECTORS = ["positive", "unknown", "wrong-profile", "incomplete", "preexisting",
             "reused-project", "partial-quota", "initialize-positive", "initialize-existing",
             "initialize-unsafe-parent", "serve-positive", "publisher-positive",
             "publisher-reassembly", "reassembly-public-private",
             "ready-public-private", "open-public-private", "verify-positive",
             "read-public", "read-private", "read-publisher", "foreign-private",
             "capabilities-update"]
HELPERS = ["initial-enrollment-proof.nix", "initial_enrollment_image.py",
           "initial_enrollment_vm.py", "native_sdk_test_image.py"]
GUEST_SCRIPTS = ["initial_enrollment_image.py", "initial_enrollment_vm.py"]
FLAGS = ["--frozen", "--offline", "-p", PACKAGE, "--example", NAME]


def require(condition, message):
    """Refuses to publish or consume an incompletely bound artifact."""
    if not condition:
        raise SystemExit(message)


def digest(path):
    """Hashes exact bytes without modifying ELF or source inputs."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected_artifact(records, metadata):
    """Checks the real event against the original Cargo target and profile."""
    packages = [item for item in metadata["packages"] if item["name"] == PACKAGE]
    candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                  and item.get("executable") and item.get("target", {}).get("name") == NAME]
    require(len(packages) == len(candidates) == 1, "ambiguous initial enrollment artifact")
    artifact = candidates[0]
    targets = [item for item in packages[0]["targets"]
               if item["name"] == NAME and item["kind"] == ["example"]]
    require(len(targets) == 1 and artifact["target"] == targets[0]
            and artifact["package_id"] == packages[0]["id"]
            and artifact["target"]["crate_types"] == ["bin"]
            and artifact["profile"] == PROFILE and artifact["features"] == [],
            "initial enrollment target/profile/features differ from Cargo identity")
    return artifact, packages[0]


def cargo_environment(executable, workspace, temporary, target, shared):
    """Captures Cargo's real launch environment without starting any role."""
    target_lib = pathlib.Path((temporary / "initial-enrollment-target-libdir").read_text().strip())
    require(target_lib.is_dir() and target_lib.resolve().is_relative_to("/nix/store"),
            "untrusted Rust runtime library directory")
    capture = temporary / "initial-enrollment-library-path"
    working = temporary / "initial-enrollment-working-directory"
    runner = temporary / "initial-enrollment-runner"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --list ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(working)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_lib.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    log = temporary / "initial-enrollment-discovery.log"
    with log.open("w") as output:
        result = subprocess.run(["cargo", "run", *FLAGS, "--", "--list"], env=environment,
                                stdout=output, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        print(log.read_text(), file=sys.stderr)
        raise SystemExit(result.returncode)
    text = capture.read_text()
    require(text.endswith("\n") and text.count("\n") == 1 and text.strip(),
            "missing genuine Cargo runtime environment")
    require(working.read_text() == str(workspace) + "\n",
            "Cargo launch working directory differs from the selected workspace")
    directories = [shared.allowed_directory(value, target) for value in text[:-1].split(":")]
    require(all(path.is_dir() for path in directories), "missing Cargo library search directory")
    return directories


def runtime_closure(executable, directories, target, shared):
    """Retains hashes of every actually selected ELF and interpreter recursively."""
    pending = deque([(executable, [])])
    visited = set()
    loaded = {}
    copied = {}
    originals = {}
    store_directories = [path for path in directories if path.resolve().is_relative_to("/nix/store")]
    while pending:
        binary, ancestors = pending.popleft()
        if binary.resolve() in visited:
            continue
        visited.add(binary.resolve())
        headers = subprocess.run(["readelf", "--program-headers", str(binary)],
                                 text=True, capture_output=True, check=True, timeout=10).stdout
        interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", headers)
        require(len(interpreters) <= 1, "ambiguous runtime interpreter")
        for value in interpreters:
            interpreter = pathlib.Path(value)
            require(interpreter.is_file() and interpreter.resolve().is_relative_to("/nix/store"),
                    "runtime interpreter escapes immutable store")
            originals[str(interpreter)] = digest(interpreter)
            pending.append((interpreter, []))
        needed, rpaths, runpath = shared.elf_dependencies(binary, target)
        inherited = ([] if runpath else rpaths) + ancestors
        search = directories + rpaths if runpath else inherited + directories
        for path in rpaths:
            if path.resolve().is_relative_to("/nix/store") and path not in store_directories:
                store_directories.append(path)
        for name in needed:
            require("/" not in name, "nonportable runtime dependency")
            if name in loaded:
                continue
            candidates = [path / name for path in search if (path / name).is_file()]
            require(candidates, "missing runtime dependency: " + name)
            library = candidates[0]
            resolved = library.resolve()
            require(resolved.is_relative_to(target.resolve()) or resolved.is_relative_to("/nix/store"),
                    "runtime dependency escapes immutable roots")
            loaded[name] = library
            if resolved.is_relative_to(target.resolve()):
                copied[name] = library
            else:
                originals[str(library)] = digest(library)
            pending.append((library, inherited))
    return copied, originals, store_directories


def build(helper_directory):
    """Installs unchanged artifacts and records the exact completed-image inputs."""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(helper_directory))
    import native_sdk_test_image as shared

    workspace = pathlib.Path.cwd()
    source = pathlib.Path(os.environ["src"])
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    output = pathlib.Path(os.environ["out"])
    require(pathlib.Path(__file__).read_bytes() == (source / "tests/terrane/initial_enrollment_image.py").read_bytes(),
            "executed image builder differs from bound source")
    require(pathlib.Path(shared.__file__).read_bytes() == (source / "tests/terrane/native_sdk_test_image.py").read_bytes(),
            "executed runtime helper differs from bound source")
    require(tomllib.loads((workspace / "Cargo.toml").read_text()).get("profile", {}).get("dev", {}) == {},
            "unreviewed development profile")
    records = [json.loads(line) for line in (temporary / "initial-enrollment-build.jsonl").read_text().splitlines()]
    metadata = json.loads((temporary / "initial-enrollment-packages.json").read_text())
    artifact, package = selected_artifact(records, metadata)
    require(pathlib.Path(package["manifest_path"]) == workspace / PACKAGE_PATH / "Cargo.toml"
            and pathlib.Path(artifact["target"]["src_path"]) == workspace / PACKAGE_PATH / "examples" / (NAME + ".rs"),
            "Cargo target belongs to another workspace")
    executable = pathlib.Path(artifact["executable"])
    require(executable.is_file() and os.access(executable, os.X_OK)
            and executable.resolve().is_relative_to(target.resolve())
            and str(executable) in artifact["filenames"]
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid Cargo executable")
    original_hash = digest(executable)
    inputs = shared.source_hashes(workspace, source)
    for name in HELPERS:
        relative = "tests/terrane/" + name
        require((workspace.parent / relative).read_bytes() == (source / relative).read_bytes(),
                "mutable proof input: " + name)
        inputs[relative] = digest(source / relative)
    directories = cargo_environment(executable, workspace, temporary, target, shared)
    copied, original_runtime, store_directories = runtime_closure(executable, directories, target, shared)
    require(digest(executable) == original_hash, "Cargo discovery changed the executable")
    require(shared.source_hashes(workspace, source) == {name: value for name, value in inputs.items()
                                                      if not name.startswith("tests/")},
            "Cargo discovery changed source bytes")
    for directory in ["bin", "lib", "share"]:
        (output / directory).mkdir()
    installed = output / "bin" / NAME
    shutil.copy2(executable, installed)
    require(digest(installed) == original_hash, "installed ELF differs from original Cargo output")
    installed_runtime = {}
    for name, path in copied.items():
        destination = output / "lib" / name
        shutil.copy2(path, destination)
        require(digest(destination) == digest(path), "installed runtime bytes changed")
        installed_runtime["lib/" + name] = digest(destination)
    retained = {}
    for name in ["build.jsonl", "build.stderr", "packages.json", "target-libdir",
                 "discovery.log", "library-path", "working-directory"]:
        filename = "initial-enrollment-" + name
        shutil.copy2(temporary / filename, output / "share" / filename)
        retained["share/" + filename] = digest(output / "share" / filename)
    installed_scripts = {}
    for name in GUEST_SCRIPTS:
        destination = output / "share" / name
        shutil.copy2(source / "tests/terrane" / name, destination)
        expected = inputs["tests/terrane/" + name]
        require(digest(destination) == expected, "installed guest script bytes changed: " + name)
        installed_scripts["share/" + name] = expected
    library_path = ":".join(map(str, [output / "lib", *store_directories]))
    inventory = subprocess.run([str(installed), "--list"],
                               env=dict(os.environ, LD_LIBRARY_PATH=library_path),
                               text=True, capture_output=True, timeout=10)
    require(inventory.returncode == 0 and inventory.stderr == "", "pure fixture inventory failed")
    listed = inventory.stdout.splitlines()
    require(listed == SELECTORS, "unexpected exact fixture selector inventory")
    identity = {"schema_version": 1, "source": str(source), "cargo_target_dir": str(target),
                "cargo_artifact": artifact, "cargo_elf_sha256": original_hash,
                "installed_elf_sha256": digest(installed), "installed_path": "bin/" + NAME,
                "input_sha256": inputs, "retained_sha256": retained,
                "installed_scripts_sha256": installed_scripts,
                "installed_runtime_sha256": installed_runtime,
                "store_runtime_sha256": original_runtime, "runtime_library_path": library_path,
                "selectors": listed, "native_cases_executed": []}
    (output / "share/runtime-library-path").write_text(library_path + "\n")
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")


def verify(image, source):
    """Consumes the completed image before VM construction and again in guest."""
    identity = json.loads((image / "share/identity.json").read_text())
    require(identity["schema_version"] == 1 and identity["source"] == str(source)
            and identity["native_cases_executed"] == [] and identity["selectors"] == SELECTORS,
            "completed image source or discovery identity differs")
    expected_names = {"share/initial-enrollment-" + name for name in [
        "build.jsonl", "build.stderr", "packages.json", "target-libdir",
        "discovery.log", "library-path", "working-directory"]}
    require(set(identity["retained_sha256"]) == expected_names, "incomplete retained Cargo evidence")
    for name, expected in identity["retained_sha256"].items():
        require(name.startswith("share/") and ".." not in pathlib.Path(name).parts
                and digest(image / name) == expected, "retained Cargo evidence changed: " + name)
    require(set(identity["installed_scripts_sha256"]) == {"share/" + name for name in GUEST_SCRIPTS},
            "incomplete installed guest script inventory")
    for name in GUEST_SCRIPTS:
        expected = identity["input_sha256"].get("tests/terrane/" + name)
        require(identity["installed_scripts_sha256"]["share/" + name] == expected
                and digest(image / "share" / name) == expected,
                "installed guest script differs from bound source: " + name)
    share_names = {path.name for path in (image / "share").iterdir()}
    require(share_names == {pathlib.PurePosixPath(name).name for name in expected_names}
            | set(GUEST_SCRIPTS) | {"identity.json", "runtime-library-path"},
            "completed image contains unrecorded share files")
    records = [json.loads(line) for line in (image / "share/initial-enrollment-build.jsonl").read_text().splitlines()]
    metadata = json.loads((image / "share/initial-enrollment-packages.json").read_text())
    artifact, package = selected_artifact(records, metadata)
    require(artifact == identity["cargo_artifact"]
            and pathlib.Path(package["manifest_path"]).parent.name == PACKAGE
            and pathlib.Path(artifact["target"]["src_path"]).parts[-3:] == (PACKAGE, "examples", NAME + ".rs")
            and pathlib.Path(artifact["executable"]).is_relative_to(identity["cargo_target_dir"]),
            "completed image does not retain its original Cargo event")
    workspace = pathlib.Path(package["manifest_path"]).parents[len(PACKAGE_PATH.parts)]
    require(pathlib.Path(package["manifest_path"]) == workspace / PACKAGE_PATH / "Cargo.toml"
            and pathlib.Path(artifact["target"]["src_path"]) == workspace / PACKAGE_PATH / "examples" / (NAME + ".rs"),
            "completed image Cargo target belongs to another workspace")
    require((image / "share/initial-enrollment-working-directory").read_text() == str(workspace) + "\n",
            "retained Cargo launch working directory differs from its original workspace")
    require(identity["installed_path"] == "bin/" + NAME, "unexpected installed executable")
    executable = image / identity["installed_path"]
    require(executable.read_bytes().startswith(b"\x7fELF")
            and digest(executable) == identity["cargo_elf_sha256"] == identity["installed_elf_sha256"],
            "installed executable was changed after Cargo")
    require(identity["input_sha256"].get("Cargo.lock") == digest(source / "crates/Cargo.lock"),
            "missing original Cargo.lock binding")
    source_names = {path.relative_to(source / "crates").as_posix()
                    for path in (source / "crates").rglob("*") if path.is_file()}
    source_names.discard(".cargo/config.toml")
    source_names.update("tests/terrane/" + name for name in HELPERS)
    require(set(identity["input_sha256"]) == source_names, "incomplete source input inventory")
    for name, expected in identity["input_sha256"].items():
        require(not pathlib.Path(name).is_absolute() and ".." not in pathlib.Path(name).parts,
                "unsafe source hash name")
        path = source / name if name.startswith("tests/") else source / "crates" / name
        require(digest(path) == expected, "immutable source input changed: " + name)
    for name in HELPERS:
        require(identity["input_sha256"].get("tests/terrane/" + name) == digest(source / "tests/terrane" / name),
                "proof helper is not bound: " + name)
    require(pathlib.Path(__file__).resolve() == image / "share/initial_enrollment_image.py"
            and pathlib.Path(__file__).read_bytes() == (source / "tests/terrane/initial_enrollment_image.py").read_bytes(),
            "executed verifier is not the bound installed script")
    for name, expected in identity["installed_runtime_sha256"].items():
        require(pathlib.PurePosixPath(name).parent == pathlib.PurePosixPath("lib")
                and digest(image / name) == expected, "installed runtime changed")
    require({path.relative_to(image).as_posix() for path in (image / "lib").iterdir()}
            == set(identity["installed_runtime_sha256"]), "unrecorded installed runtime library")
    for name, expected in identity["store_runtime_sha256"].items():
        path = pathlib.Path(name)
        require(path.is_file() and path.resolve().is_relative_to("/nix/store")
                and digest(path) == expected, "immutable runtime closure changed: " + name)
    require(identity["store_runtime_sha256"], "missing immutable runtime/interpreter binding")
    library_path = (image / "share/runtime-library-path").read_text().strip()
    paths = [pathlib.Path(value) for value in library_path.split(":")]
    require(library_path == identity["runtime_library_path"] and paths[0] == image / "lib"
            and all(path.is_dir() and (path == image / "lib" or path.resolve().is_relative_to("/nix/store")) for path in paths),
            "completed image runtime search path changed")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "tests/terrane"))
    import native_sdk_test_image as shared

    require(pathlib.Path(shared.__file__).read_bytes() == (source / "tests/terrane/native_sdk_test_image.py").read_bytes(),
            "executed ELF verifier helper differs from bound source")
    copied, actual_closure, _ = runtime_closure(executable, paths, pathlib.Path(identity["cargo_target_dir"]), shared)
    expected_closure = dict(identity["store_runtime_sha256"])
    expected_closure.update({str(image / name): expected
                             for name, expected in identity["installed_runtime_sha256"].items()})
    require(not copied and actual_closure == expected_closure,
            "completed installed ELF resolves a different runtime/interpreter closure")
    print("PASS completed initial-enrollment image identity; native cases remain unexecuted", flush=True)


def main():
    """Selects only build, completed-image verification or error rendering."""
    if len(sys.argv) == 3 and sys.argv[1] == "errors":
        for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(line)
                continue
            rendered = event.get("message", {}).get("rendered")
            if rendered:
                print(rendered, end="")
    elif len(sys.argv) == 3 and sys.argv[1] == "build":
        build(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        verify(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    else:
        raise SystemExit("expected build HELPERS | verify IMAGE SOURCE | errors CARGO_JSON")


if __name__ == "__main__":
    main()

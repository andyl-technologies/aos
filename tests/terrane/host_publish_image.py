"""Binds the native publication example and reachable ELF runtime to source.

Discovery intercepts Cargo's runner without executing native assertions. Actual
fixture selectors execute only in their separately supervised guest processes.
"""

import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, sys.argv[1])
from native_sdk_test_image import allowed_directory, require, runtime_closure, source_hashes

workspace = pathlib.Path.cwd()
temporary = pathlib.Path(os.environ["TMPDIR"])
target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
source = pathlib.Path(os.environ["src"])
output = pathlib.Path(os.environ["out"])
packages = json.loads((temporary / "publication-packages.json").read_text())["packages"]
package = [item for item in packages
           if pathlib.Path(item["manifest_path"]) == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
require(len(package) == 1 and package[0]["name"] == "terrane-linux",
        "ambiguous publication source package")
manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
require(manifest.get("profile", {}).get("dev", {}) == {},
        "publication workspace dev profile overrides the expected Cargo defaults")
records = [json.loads(line) for line in
           (temporary / "publication-build.jsonl").read_text().splitlines()]
selected = [item for item in records if item.get("reason") == "compiler-artifact"
            and item.get("target", {}).get("name") == "publication_fixture"]
require(len(selected) == 1, "ambiguous publication executable")
artifact = selected[0]
executable = pathlib.Path(artifact.get("executable") or "")
require(artifact["package_id"] == package[0]["id"]
        and artifact["target"]["kind"] == ["example"]
        and artifact["target"]["crate_types"] == ["bin"]
        and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/examples/publication_fixture.rs"
        and artifact["profile"]["test"] is False
        and artifact["profile"]["opt_level"] == "0"
        and artifact["profile"]["debug_assertions"] is True
        and artifact["profile"]["debuginfo"] == 2
        and artifact["profile"]["overflow_checks"] is True
        and sorted(artifact["features"]) == ["native-test-fixtures", "tokio"]
        and executable.is_file() and os.access(executable, os.X_OK)
        and executable.resolve().is_relative_to(target.resolve()),
        "publication artifact source/profile mismatch")
bound_executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
hashes = source_hashes(workspace, source)
target_libraries = pathlib.Path((temporary / "publication-rust-libdir").read_text().strip())
require(target_libraries.is_dir() and target_libraries.resolve().is_relative_to("/nix/store"),
        "untrusted Rust target libraries")
capture = temporary / "publication-cargo-library-path"
cwd_capture = temporary / "publication-cargo-working-directory"
runner = temporary / "publication-discovery-runner"
runner.write_text("\n".join([
    f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
    '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --discover ]',
    "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
    "pwd -P > " + shlex.quote(str(cwd_capture)),
    "exit 0", "",
]))
runner.chmod(0o755)
environment = dict(os.environ)
triple = target_libraries.parent.name.upper().replace("-", "_")
environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
with (temporary / "publication-cargo-discovery.log").open("w") as log:
    subprocess.run(["cargo", "run", "--frozen", "--offline", "-p", "terrane-linux",
                    "--features", "native-test-fixtures", "--example", "publication_fixture",
                    "--", "--discover"], env=environment,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
require(hashlib.sha256(executable.read_bytes()).hexdigest() == bound_executable_sha256,
        "Cargo discovery changed the selected publication executable")
captured = capture.read_text()
require(captured.endswith("\n") and captured.count("\n") == 1 and captured.strip(),
        "missing Cargo runtime environment")
require(cwd_capture.read_text() == str(workspace) + "\n", "Cargo launch directory mismatch")
directories = [allowed_directory(item, target) for item in captured[:-1].split(":")]
require(all(directory.is_dir() for directory in directories), "missing Cargo library directory")
libraries, store_directories = runtime_closure(executable, directories, target)
require(hashes == source_hashes(workspace, source), "source changed during discovery")
for directory in ["bin", "libexec", "lib", "share"]:
    (output / directory).mkdir()
installed = output / "libexec/terrane-publication-fixture"
require(hashlib.sha256(executable.read_bytes()).hexdigest() == bound_executable_sha256,
        "publication executable changed before installation")
shutil.copy2(executable, installed)
require(hashlib.sha256(installed.read_bytes()).hexdigest() == bound_executable_sha256
        and hashlib.sha256(executable.read_bytes()).hexdigest() == bound_executable_sha256,
        "publication executable changed while copying the bound artifact")
for name, library in libraries.items():
    shutil.copy2(library, output / "lib" / name)
library_path = ":".join(map(str, [output / "lib", *store_directories]))
wrapper = output / "bin/terrane-publication-fixture"
wrapper.write_text("\n".join([
    f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
    "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
    "exec " + shlex.quote(str(installed)) + ' "$@"', "",
]))
wrapper.chmod(0o755)
identity = {"schema_version": 1, "cargo_profile": "dev", "default_features": True,
            "requested_features": ["native-test-fixtures"], "source": str(source), "package_id": artifact["package_id"],
            "target": artifact["target"], "profile": artifact["profile"],
            "features": artifact["features"], "input_sha256": hashes,
            "executable_sha256": bound_executable_sha256,
            "copied_runtime_libraries": sorted(libraries),
            "copied_runtime_sha256": {name: hashlib.sha256((output / "lib" / name).read_bytes()).hexdigest()
                                      for name in sorted(libraries)},
            "runtime_library_path": library_path}
(output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
for name in ["publication-build.jsonl", "publication-packages.json",
             "publication-cargo-discovery.log"]:
    shutil.copy2(temporary / name, output / "share" / name)

require(hashlib.sha256(installed.read_bytes()).hexdigest() == identity["executable_sha256"],
        "installed publication fixture differs from selected Cargo executable")
require(hashes == source_hashes(workspace, source), "publication image installation changed source")

"""Binds the Cargo example and its reachable ELF runtime to immutable source."""

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
packages = json.loads((temporary / "confinement-packages.json").read_text())["packages"]
package = [item for item in packages
           if pathlib.Path(item["manifest_path"]) == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
require(len(package) == 1 and package[0]["name"] == "terrane-linux",
        "ambiguous confinement source package")
records = [json.loads(line) for line in
           (temporary / "confinement-artifacts.jsonl").read_text().splitlines()]
selected = [item for item in records if item.get("reason") == "compiler-artifact"
            and item.get("target", {}).get("name") == "quota_confinement_fixture"]
require(len(selected) == 1, "ambiguous confinement executable")
artifact = selected[0]
executable = pathlib.Path(artifact.get("executable") or "")
manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
# This workspace leaves Cargo's development profile unchanged: opt-level zero,
# debug assertions enabled and full debug information (level two). Refuse an
# override rather than silently publishing a different qualification artifact.
require(manifest.get("profile", {}).get("dev", {}) == {},
        "unreviewed development profile override")
require(artifact["package_id"] == package[0]["id"]
        and artifact["target"]["kind"] == ["example"]
        and artifact["target"]["crate_types"] == ["bin"]
        and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/examples/quota_confinement_fixture.rs"
        and artifact["profile"]["test"] is False
        and artifact["profile"]["opt_level"] == "0"
        and artifact["profile"]["debug_assertions"] is True
        and artifact["profile"]["overflow_checks"] is True
        and artifact["profile"]["debuginfo"] == 2
        and sorted(artifact["features"]) == ["tokio"]
        and executable.is_file() and os.access(executable, os.X_OK)
        and executable.resolve().is_relative_to(target.resolve()),
        "confinement artifact source/profile mismatch")
hashes = source_hashes(workspace, source)
executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
target_libraries = pathlib.Path((temporary / "confinement-target-libdir").read_text().strip())
require(target_libraries.is_dir() and target_libraries.resolve().is_relative_to("/nix/store"),
        "untrusted Rust target libraries")
capture = temporary / "confinement-cargo-library-path"
cwd_capture = temporary / "confinement-cargo-working-directory"
runner = temporary / "confinement-discovery-runner"
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
with (temporary / "confinement-cargo-discovery.log").open("w") as log:
    subprocess.run(["cargo", "run", "--frozen", "--offline", "-p", "terrane-linux",
                    "--features", "tokio", "--example", "quota_confinement_fixture",
                    "--", "--discover"], env=environment,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
require(hashlib.sha256(executable.read_bytes()).hexdigest() == executable_hash,
        "Cargo discovery replaced the selected confinement executable")
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
installed = output / "libexec/quota-confinement-fixture"
shutil.copy2(executable, installed)
require(hashlib.sha256(installed.read_bytes()).hexdigest() == executable_hash,
        "installed confinement executable differs from the selected artifact")
for name, library in libraries.items():
    shutil.copy2(library, output / "lib" / name)
library_path = ":".join(map(str, [output / "lib", *store_directories]))
wrapper = output / "bin/quota-confinement-fixture"
wrapper.write_text("\n".join([
    f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
    "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
    "exec " + shlex.quote(str(installed)) + ' "$@"', "",
]))
wrapper.chmod(0o755)
identity = {"schema_version": 1, "source": str(source), "package_id": artifact["package_id"],
            "cargo_profile": "dev", "requested_features": ["tokio"],
            "target": artifact["target"], "profile": artifact["profile"],
            "features": artifact["features"], "input_sha256": hashes,
            "executable_sha256": executable_hash,
            "copied_runtime_libraries": sorted(libraries), "runtime_library_path": library_path}
(output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
for name in ["confinement-artifacts.jsonl", "confinement-packages.json",
             "confinement-cargo-discovery.log"]:
    shutil.copy2(temporary / name, output / "share" / name)

# The guest checks retained bytes after package fixups and rootfs copying,
# including the wrapper and runtime libraries that actually launch the ELF.
checksums = []
for path in sorted(output.rglob("*")):
    if path.is_file():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {path.relative_to(output)}")
(output / "share/checksums.sha256").write_text("\n".join(checksums) + "\n")

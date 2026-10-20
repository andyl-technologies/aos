"""Binds the helper proof image to exact Cargo artifacts and reachable runtimes.

The image records execution separately from compilation. Ignored administrative
and native fixtures acquire no execution credit until their explicit VM run.
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

sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import native_sdk_test_image as closure_helper
from native_sdk_test_image import allowed_directory, require, runtime_closure, source_hashes

EXPECTED = {
    "terrane_linux": {
        "kernel_peer_identity_is_not_a_packet_assertion",
        "oversized_native_packet_is_rejected_after_receive_truncation",
        "descriptor_ancillary_is_rejected_without_returning_custody",
    },
    "host_quota_protocol": {
        "query_rejects_ambiguous_extended_or_truncated_packets",
        "error_response_cannot_smuggle_quota_evidence",
        "nonroot_helper_identity_cannot_mint_native_evidence",
        "provisioning_guard_excludes_factories_until_exclusive_custody_ends",
    },
    "aos_terrane_integration": {
        "host::claims::tests::permanent_publication_survives_restart_and_refuses_collision",
        "host::claims::tests::stale_temporary_name_is_preserved_and_skipped",
        "host::claims::tests::concurrent_claims_publish_one_complete_record",
        "host::claims::tests::host_global_claims_preserve_crash_custody_vm",
        "host::claims::provision_tests::host_global_provision_worker_vm",
        "host::claims::provision_tests::host_global_provision_kill_restart_and_broker_vm",
    },
    "host_quota_config": {
        "configuration_rejects_mutation_command_fields",
        "host_quota_admin_ledger_preserves_domain_and_project_vm",
    },
    "host_quota_native": {
        "host_quota_native_privilege_and_helper_vm",
        "host_quota_vm_role",
    },
}
PROFILE = {
    "opt_level": "s", "debuginfo": 0, "debug_assertions": True,
    "overflow_checks": True, "test": True,
}


PACKAGE_PATHS = {'terrane-format': 'terrane/sdk/terrane-format', 'terrane-sdk': 'terrane/sdk/terrane-sdk', 'terrane-linux': 'terrane/linux/terrane-linux', 'terrane-cli': 'terrane/cli/terrane-cli', 'aos-terrane-integration': 'terrane/integration/aos-terrane-integration'}


def sha256(path):
    """Hashes the exact selected or installed bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_artifacts(workspace, temporary, target):
    """Rejects foreign packages, targets, profiles, features and duplicate records."""
    packages = json.loads((temporary / "host-quota-packages.json").read_text())["packages"]
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"},
            "unreviewed helper test profile")
    records = [json.loads(line) for line in
               (temporary / "host-quota-build.jsonl").read_text().splitlines()]
    selected = {}
    for name in EXPECTED:
        crate = "aos-terrane-integration" if name in {"aos_terrane_integration", "host_quota_config"} else "terrane-linux"
        kind = ["lib"] if name in {"aos_terrane_integration", "terrane_linux"} else ["test"]
        source = "src/lib.rs" if kind == ["lib"] else f"tests/{name}.rs"
        package = [item for item in packages if pathlib.Path(item["manifest_path"])
                   == workspace / PACKAGE_PATHS[crate] / "Cargo.toml"]
        require(len(package) == 1 and package[0]["name"] == crate,
                f"ambiguous helper source package: {name}")
        candidates = [record for record in records if record.get("reason") == "compiler-artifact"
                      and record.get("target", {}).get("name") == name
                      and record.get("profile", {}).get("test") is True]
        require(len(candidates) == 1, f"ambiguous helper test artifact: {name}")
        artifact = candidates[0]
        targets = [item for item in package[0]["targets"] if item["name"] == name
                   and item["kind"] == kind]
        require(len(targets) == 1, f"ambiguous helper metadata target: {name}")
        executable = pathlib.Path(artifact.get("executable") or "")
        require(artifact["package_id"] == package[0]["id"]
                and artifact["target"] == targets[0]
                and artifact["target"]["crate_types"] == (["lib"] if kind == ["lib"] else ["bin"])
                and pathlib.Path(artifact["target"]["src_path"]) == workspace / PACKAGE_PATHS[crate] / source
                and artifact["features"] == [] and artifact["profile"] == PROFILE
                and str(executable) in artifact["filenames"]
                and executable.is_file() and os.access(executable, os.X_OK)
                and executable.resolve().is_relative_to(target.resolve()),
                f"helper source/target/features/profile mismatch: {name}")
        require(executable.read_bytes().startswith(b"\x7fELF"), f"non-ELF helper artifact: {name}")
        selected[name] = (artifact, executable, sha256(executable), crate)
    return selected


def launch_directories(executable, crate, workspace, temporary, target):
    """Captures a genuine Cargo test launch while executing only libtest --list."""
    libraries = pathlib.Path((temporary / "host-quota-rust-libdir").read_text().strip())
    require(libraries.is_dir() and libraries.resolve().is_relative_to("/nix/store"),
            "untrusted helper target library directory")
    capture = temporary / f"host-quota-{crate}-library-path"
    working = temporary / f"host-quota-{crate}-working-directory"
    runner = temporary / f"host-quota-{crate}-runner"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --list ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(working)), 'exec "$@"', "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = libraries.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    with (temporary / f"host-quota-{crate}-discovery.log").open("w") as log:
        subprocess.run(["cargo", "test", "--frozen", "--offline", "-p", crate,
                        "--lib", "--", "--list"], env=environment, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    captured = capture.read_text()
    require(captured.endswith("\n") and captured.count("\n") == 1 and captured.strip(),
            "missing helper Cargo runtime environment")
    require(working.read_text() == str(workspace / PACKAGE_PATHS[crate]) + "\n",
            "helper Cargo test working directory mismatch")
    directories = [allowed_directory(value, target) for value in captured[:-1].split(":")]
    require(all(directory.is_dir() for directory in directories), "missing helper runtime directory")
    return directories


def install_and_execute():
    """Publishes exact ELF identities, runtime closure and actual local execution."""
    workspace = pathlib.Path.cwd()
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    source = pathlib.Path(os.environ["src"])
    output = pathlib.Path(os.environ["out"])
    require(pathlib.Path(__file__).read_bytes()
            == (source / "crates/terrane/integration/aos-terrane-integration/src/host/proof_image.py").read_bytes(),
            "executed helper image installer differs from immutable source")
    require(pathlib.Path(closure_helper.__file__).read_bytes()
            == (source / "tests/terrane/native_sdk_test_image.py").read_bytes(),
            "executed ELF closure helper differs from immutable source")
    selected = select_artifacts(workspace, temporary, target)
    hashes = source_hashes(workspace, source)
    for name in ["host-quota-proof.nix", "native_sdk_test_image.py"]:
        path = source / "tests/terrane" / name
        require(path.read_bytes() == (workspace.parent / "tests/terrane" / name).read_bytes(),
                f"helper proof input changed: {name}")
        hashes[f"tests/terrane/{name}"] = sha256(path)
    directories = {}
    for name in ["terrane_linux", "aos_terrane_integration"]:
        artifact, executable, digest, crate = selected[name]
        directories[crate] = launch_directories(executable, crate, workspace, temporary, target)
    libraries = {}
    store_directories = []
    for artifact, executable, digest, crate in selected.values():
        require(sha256(executable) == digest, "Cargo discovery replaced a helper artifact")
        reachable, store = runtime_closure(executable, directories[crate], target)
        for name, path in reachable.items():
            require(name not in libraries or libraries[name].read_bytes() == path.read_bytes(),
                    f"ambiguous installed helper runtime: {name}")
            libraries[name] = path
        for path in store:
            if path not in store_directories:
                store_directories.append(path)
    for name in ["bin", "lib", "share"]:
        (output / name).mkdir()
    library_hashes = {}
    for name, path in libraries.items():
        shutil.copy2(path, output / "lib" / name)
        library_hashes[name] = sha256(path)
        require(sha256(output / "lib" / name) == library_hashes[name],
                f"installed helper runtime changed: {name}")
    library_path = ":".join(map(str, [output / "lib", *store_directories]))
    (output / "share/runtime-library-path").write_text(library_path + "\n")
    environment = dict(os.environ, LD_LIBRARY_PATH=library_path)
    identities = {}
    evidence = {}
    checksums = []
    for name, (artifact, executable, digest, crate) in selected.items():
        installed = output / "bin" / name
        shutil.copy2(executable, installed)
        require(sha256(installed) == digest, f"installed helper ELF changed: {name}")
        prefix = "host_quota::socket::tests::" if name == "terrane_linux" else ""
        listed = subprocess.run([str(installed), "--list", "--format", "terse"],
                                check=True, text=True, capture_output=True, env=environment).stdout
        actual = {line.removesuffix(": test").removeprefix(prefix) for line in listed.splitlines()
                  if line.endswith(": test") and line.startswith(prefix)}
        require(actual == EXPECTED[name], f"helper exact inventory mismatch: {name}: {actual}")
        evidence[name] = {"inventory": sorted(actual), "executed": []}
        if name != "host_quota_native":
            for case in sorted(actual):
                if case.endswith("_vm"):
                    continue
                result = subprocess.run([str(installed), "--exact", prefix + case, "--nocapture"],
                                        check=True, text=True, capture_output=True, env=environment)
                require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                        f"helper case did not execute exactly once: {case}")
                evidence[name]["executed"].append({"case": case, "stdout": result.stdout,
                                                "stderr": result.stderr})
        require(sha256(executable) == digest and sha256(installed) == digest,
                f"helper ELF changed during discovery or execution: {name}")
        identities[name] = {"cargo_artifact": artifact, "cargo_elf_sha256": digest,
                            "installed_elf_sha256": sha256(installed),
                            "installed_path": f"bin/{name}", "package": crate,
                            "default_features": True, "requested_features": []}
        checksums.append(f"{digest}  bin/{name}\n")
    for name, digest in library_hashes.items():
        checksums.append(f"{digest}  lib/{name}\n")
    identity = {"schema_version": 1, "source": str(source), "input_sha256": hashes,
                "artifacts": identities, "runtime_library_path": library_path,
                "copied_runtime_library_sha256": library_hashes}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/elf-sha256sum").write_text("".join(checksums))
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    for name in ["host-quota-build.jsonl", "host-quota-packages.json", "host-quota-rust-libdir"]:
        shutil.copy2(temporary / name, output / "share" / name)
    for crate in directories:
        for suffix in ["library-path", "working-directory", "discovery.log"]:
            name = f"host-quota-{crate}-{suffix}"
            shutil.copy2(temporary / name, output / "share" / name)


if __name__ == "__main__":
    install_and_execute()

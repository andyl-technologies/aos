"""Binds strict transport test inventories to source and reachable ELF runtimes."""

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

FEATURES = ["native-test-fixtures", "tokio"]
# These original mode controls need the guest's actual ext4 setgid operations.
SETGID_SOCKET_CASES = {
    "retained_socket_chmod_sets_exact_mode_without_changing_inode_or_group",
    "replaced_socket_name_is_rejected_without_changing_either_inode",
    "socket_chmod_rejects_wrong_type_and_owner_before_mutation",
}
EXPECTED = {
    "terrane_linux": {
        "kernel_peer_credentials_cannot_be_claimed_in_packet",
        "configured_domain_selection_has_no_fallback",
        "real_seqpacket_roundtrip_requires_response_correlation",
        "duplicate_active_request_is_rejected_before_dispatch",
        "unsolicited_and_mismatched_responses_are_rejected",
        "oversized_payload_and_excess_rights_are_rejected",
        "received_rights_are_close_on_exec_and_writable_sources_fail",
        "rejected_rights_do_not_accumulate_descriptors",
        "ancillary_truncation_and_unregistered_credentials_are_rejected",
        "retained_socket_chmod_sets_exact_mode_without_changing_inode_or_group",
        "replaced_socket_name_is_rejected_without_changing_either_inode",
        "socket_chmod_rejects_wrong_type_and_owner_before_mutation",
    },
    "publisher_local_protocol": {
        "quarantine_inspection_returns_only_one_unverified_descriptor",
        "quarantine_requires_an_exact_body_incarnation_and_returns_no_authority",
        "registered_probe_roundtrips_without_descriptors",
        "unknown_fields_fail_at_every_message_depth",
        "duplicate_singular_wrong_wire_and_boolean_fields_fail",
        "explicit_unexpected_default_fields_fail",
        "payload_and_varint_bounds_fail_before_decode",
        "publication_requires_exact_source_and_metadata_counts",
        "claim_key_profile_and_retention_mismatches_fail",
        "recovery_and_retirement_field_matrix_is_closed",
        "error_responses_have_no_binding_token_or_descriptors",
        "header_direction_domain_version_and_budget_are_checked",
    },
    "publisher_local_vm": {"publisher_local_multuid_vm", "publisher_local_vm_role"},
    "publisher_local_native": {"publisher_local_native_lifecycle_vm", "publisher_local_native_role"},
}
# All socket cases exercise actual kernel state, including descriptor import
# and temporary files. Image construction only discovers their original names.
NATIVE_SOCKET_CASES = EXPECTED["terrane_linux"]


def sha256(path):
    """Binds selected executable bytes before discovery and installation."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_captured(command, environment):
    """Retains the original child diagnostics before failing qualification."""
    result = subprocess.run(command, text=True, capture_output=True, env=environment)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"transport proof command failed ({result.returncode}): {command}")
    return result


def select_artifacts(workspace, temporary, target):
    """Selects only exact package targets with reviewed test/dev profiles."""
    packages = json.loads((temporary / "publisher-local-packages.json").read_text())["packages"]
    package = [item for item in packages if pathlib.Path(item["manifest_path"])
               == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
    require(len(package) == 1 and package[0]["name"] == "terrane-linux", "ambiguous transport package")
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(manifest.get("profile", {}).get("dev", {}) == {}, "unreviewed development profile")
    require(manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"},
            "unreviewed test profile")
    records = [json.loads(line) for line in
               (temporary / "publisher-local-build.jsonl").read_text().splitlines()]
    selected = {}
    for name in [*EXPECTED, "publication_fixture"]:
        is_test = name != "publication_fixture"
        candidates = [record for record in records if record.get("reason") == "compiler-artifact"
                      and record.get("target", {}).get("name") == name
                      and record.get("profile", {}).get("test") is is_test]
        require(len(candidates) == 1, f"ambiguous transport executable: {name}")
        artifact = candidates[0]
        kind = ["lib"] if name == "terrane_linux" else ["test"] if is_test else ["example"]
        source = "src/lib.rs" if name == "terrane_linux" else (
            f"tests/{name}.rs" if is_test else "examples/publication_fixture.rs")
        targets = [item for item in package[0]["targets"] if item["name"] == name
                   and item["kind"] == kind]
        require(len(targets) == 1, f"ambiguous metadata target: {name}")
        executable = pathlib.Path(artifact.get("executable") or "")
        profile = artifact["profile"]
        require(artifact["package_id"] == package[0]["id"]
                and artifact["target"] == targets[0]
                and artifact["target"]["kind"] == kind
                and artifact["target"]["crate_types"] == (["lib"] if name == "terrane_linux" else ["bin"])
                and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux" / source
                and sorted(artifact["features"]) == FEATURES
                and profile["opt_level"] == ("s" if is_test else "0")
                and profile["debug_assertions"] is True
                and profile["debuginfo"] == (0 if is_test else 2)
                and executable.is_file() and os.access(executable, os.X_OK)
                and executable.resolve().is_relative_to(target.resolve()),
                f"transport source/target/profile mismatch: {name}")
        selected[name] = (artifact, executable, sha256(executable))
    return selected


def launch_directories(executable, workspace, temporary, target):
    """Captures the actual Cargo launch environment without running role code."""
    target_libraries = pathlib.Path((temporary / "publisher-local-rust-libdir").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.resolve().is_relative_to("/nix/store"),
            "untrusted target library directory")
    capture = temporary / "publisher-local-cargo-library-path"
    cwd_capture = temporary / "publisher-local-cargo-working-directory"
    runner = temporary / "publisher-local-discovery-runner"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = --discover ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(cwd_capture)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_libraries.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    discovery_log = temporary / "publisher-local-cargo-discovery.log"
    with discovery_log.open("w") as log:
        discovery = subprocess.run(
            ["cargo", "run", "--frozen", "--offline", "-p", "terrane-linux",
             "--features", "native-test-fixtures", "--example", "publication_fixture",
             "--", "--discover"], env=environment, stdout=log, stderr=subprocess.STDOUT)
    if discovery.returncode != 0:
        sys.stderr.write(discovery_log.read_text())
        raise SystemExit("transport Cargo runtime discovery failed")
    captured = capture.read_text()
    require(captured.endswith("\n") and captured.count("\n") == 1 and captured.strip(),
            "missing Cargo runtime environment")
    require(cwd_capture.read_text() == str(workspace) + "\n", "Cargo launch directory mismatch")
    directories = [allowed_directory(value, target) for value in captured[:-1].split(":")]
    require(all(directory.is_dir() for directory in directories), "missing Cargo runtime directory")
    return directories


def install_and_execute():
    """Installs exact artifacts and executes every selected local case once."""
    workspace = pathlib.Path.cwd()
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    source = pathlib.Path(os.environ["src"])
    output = pathlib.Path(os.environ["out"])
    selected = select_artifacts(workspace, temporary, target)
    hashes = source_hashes(workspace, source)
    for name in ["publisher_local_proof.py", "native_sdk_test_image.py",
                 "publisher-local-proof.nix", "native_socket_units.bash"]:
        path = source / "tests/terrane" / name
        hashes[f"tests/terrane/{name}"] = sha256(path)
    directories = launch_directories(selected["publication_fixture"][1], workspace, temporary, target)
    libraries = {}
    store_directories = []
    for artifact, executable, digest in selected.values():
        require(sha256(executable) == digest, "Cargo discovery replaced a selected transport artifact")
        reachable, store = runtime_closure(executable, directories, target)
        for name, path in reachable.items():
            require(name not in libraries or libraries[name].read_bytes() == path.read_bytes(),
                    f"ambiguous transport runtime library: {name}")
            libraries[name] = path
        for path in store:
            if path not in store_directories:
                store_directories.append(path)
    for directory in ["bin", "libexec", "lib", "share"]:
        (output / directory).mkdir()
    for name, path in libraries.items():
        shutil.copy2(path, output / "lib" / name)
    library_path = ":".join(map(str, [output / "lib", *store_directories]))
    environment = dict(os.environ, LD_LIBRARY_PATH=library_path)
    identities = {}
    for name, (artifact, executable, digest) in selected.items():
        installed = output / "libexec" / name
        shutil.copy2(executable, installed)
        require(sha256(installed) == digest, f"installed transport executable changed: {name}")
        wrapper = output / "bin" / name
        wrapper.write_text("\n".join([
            f'#!{os.environ["CONFIG_SHELL"]}', "set -eu",
            "export LD_LIBRARY_PATH=" + shlex.quote(library_path),
            "exec " + shlex.quote(str(installed)) + ' "$@"', "",
        ]))
        wrapper.chmod(0o755)
        identities[name] = {"package_id": artifact["package_id"], "target": artifact["target"],
                            "profile": artifact["profile"], "features": artifact["features"],
                            "executable_sha256": digest}
    fixture = output / "bin/publication_fixture"
    listed = run_captured([str(fixture), "--list"], environment).stdout
    selectors = [line for line in listed.splitlines() if line.startswith("transport:")]
    require(sorted(selectors) == ["transport:native-client", "transport:native-publisher"],
            "fresh-process transport selector inventory mismatch")
    evidence = {"fresh-process-fixture": {"inventory": selectors, "executed": []}}
    for name, expected in EXPECTED.items():
        executable = output / "bin" / name
        prefix = "publisher_local::socket::tests::" if name == "terrane_linux" else ""
        listed = run_captured([str(executable), "--list", "--format", "terse"], environment).stdout
        actual = [line.removesuffix(": test").removeprefix(prefix) for line in listed.splitlines()
                  if line.endswith(": test") and line.startswith(prefix)]
        require(len(actual) == len(set(actual)) and set(actual) == expected,
                f"publisher-local exact inventory mismatch: {name}: {actual}")
        evidence[name] = {"inventory": sorted(actual), "executed": []}
        if name in {"terrane_linux", "publisher_local_vm", "publisher_local_native"}:
            continue
        for case in sorted(actual):
            result = run_captured([str(executable), "--exact", prefix + case, "--nocapture"],
                                  environment)
            require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                    f"publisher-local test did not execute exactly once: {case}")
            evidence[name]["executed"].append({"case": case, "stdout": result.stdout, "stderr": result.stderr})
    require(source_hashes(workspace, source) == {key: value for key, value in hashes.items()
                                               if not key.startswith("tests/")},
            "source changed during transport discovery/execution")
    require(len(NATIVE_SOCKET_CASES) == 12 and len(SETGID_SOCKET_CASES) == 3
            and SETGID_SOCKET_CASES <= NATIVE_SOCKET_CASES,
            "native socket inventory must retain all twelve original source cases")
    native_cases = ["publisher_local::socket::tests::" + case
                    for case in sorted(NATIVE_SOCKET_CASES)]
    (output / "share/native-socket-cases").write_text("\n".join(native_cases) + "\n")
    shutil.copy2(source / "tests/terrane/native_socket_units.bash",
                 output / "share/native_socket_units.bash")
    identity = {"schema_version": 1, "source": str(source), "requested_features": ["native-test-fixtures"],
                "input_sha256": hashes, "artifacts": identities,
                "copied_runtime_libraries": {name: sha256(path) for name, path in libraries.items()},
                "runtime_library_path": library_path, "tests": evidence,
                "native_socket_tests": native_cases}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    for name in ["publisher-local-build.jsonl", "publisher-local-packages.json",
                 "publisher-local-cargo-discovery.log"]:
        shutil.copy2(temporary / name, output / "share" / name)


if __name__ == "__main__":
    install_and_execute()

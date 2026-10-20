"""Installs exact source-bound native cache component executables and ELF closure."""

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

sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import native_sdk_test_image as shared

TARGETS = {
    "host_cache_fixture": ("terrane-linux", "example", "examples/host_cache_fixture.rs", ["native-test-fixtures", "tokio"]),
    "terrane": ("terrane-cli", "bin", "src/main.rs", []),
    "aos-terrane-host": ("aos-terrane-integration", "bin", "src/bin/aos-terrane-host.rs", []),
}
PROFILE = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
           "overflow_checks": True, "test": False}

UNIT_NAME = "terrane-fs-unit"
UNIT_PREFIXES = ("host_cache::owner::", "host_cache::recovery_inspection::",
                 "publisher_local::client::recovery_manifest::")
UNIT_PROFILE = {"opt_level": "s", "debuginfo": 0, "debug_assertions": True,
                "overflow_checks": True, "test": True}
UNIT_TESTS = (
    'host_cache::owner::publication::eviction::activity::tests::verified_read_order_keeps_first_promotion_separate_from_later_hits',
    'host_cache::owner::publication::eviction::activity::tests::concurrent_verified_reads_share_one_order_without_losing_first_hits',
    'host_cache::owner::publication::residence::view::tests::close_refuses_new_reads_until_started_backing_is_dropped',
    'host_cache::owner::publication::residence::view::tests::concurrent_close_does_not_report_quiescence_during_backing_destruction',
    'host_cache::owner::consumer::sweep::tests::delayed_sweep_uses_original_expiry_and_never_restarts_grace',
    'host_cache::owner::consumer::sweep::tests::explicit_grace_has_no_second_grace_and_retained_producers_do_not_expire',
    'host_cache::owner::consumer::sweep::tests::partial_pin_expiry_is_persisted_without_releasing_the_remaining_owner',
    'host_cache::owner::admission::io::tests::actual_admission_byte_check_is_positioned_and_rejects_modified_inode_bytes',
    'host_cache::owner::admission::memory::tests::simultaneous_active_copies_and_state_headers_are_checked',
    'host_cache::owner::admission::metadata::tests::actual_metadata_pair_rejects_wrong_index_key_class_and_window',
    'host_cache::owner::admission::tests::cancelled_started_phase_faults_without_native_authority_or_mutexes',
    'host_cache::owner::admission::tests::untrusted_pair_input_is_bounded_with_checked_addition',
    'host_cache::owner::snapshot::tests::actual_snapshot_io_retains_readback_and_rejects_replaced_inode',
    'host_cache::owner::config::tests::native_host_cache_config_refuses_ambiguous_custody_and_unfunded_capacity',
    'host_cache::owner::config::tests::native_host_cache_config_validation_needs_no_existing_paths',
    'host_cache::owner::config::tests::native_index_repair_policy_defaults_closed_and_funds_payload_overlap',
    'host_cache::owner::index_io::tests::classified_index_open_reads_regular_inode_and_refuses_fifo_and_symlink',
    'host_cache::owner::index_io::tests::classified_index_open_refuses_character_device_before_read_open',
    'host_cache::owner::index_io::tests::invalid_index_error_preserves_typed_source',
    'host_cache::owner::recovery_inline::tests::inline_reconstruction_keeps_each_exact_whole_chunk_range',
    'host_cache::owner::recovery_manifest_state::tests::changed_residence_cannot_pass_a_policy_snapshot_comparison',
    'host_cache::owner::recovery_manifest_state::tests::extra_cold_rows_are_refused_and_preserved',
    'host_cache::owner::recovery_namespace::tests::actual_directory_reopen_retains_classified_inode_across_name_replacement',
    'host_cache::owner::recovery_namespace::tests::actual_name_scan_counts_coordination_unknown_and_non_utf8_entries',
    'host_cache::owner::recovery_residences::tests::conflicts_and_capacity_are_refused_without_clearing_prior_candidates',
    'host_cache::owner::recovery_residences::tests::repeated_occurrences_select_one_stable_range_independent_of_scan_order',
    'host_cache::owner::recovery_cold::tests::cold_pins_require_complete_verified_backing_without_erasing_candidates',
    'host_cache::owner::recovery_cold::tests::cold_metadata_pins_require_the_separate_verified_source_closure',
    'host_cache::owner::recovery_state_parent::tests::actual_state_parent_scan_refuses_unknown_file_and_directory_siblings',
    'host_cache::owner::retention::recovery_manifest::tests::abandoned_rpc_effect_faults_without_a_state_or_client_lock',
    'host_cache::owner::retention::recovery_manifest::tests::cancelled_in_flight_retention_never_reactivates_the_live_phase',
    'host_cache::owner::retention::recovery_manifest::tests::only_reconciled_retention_returns_to_active',
    'host_cache::owner::retention::recovery_manifest::tests::reconciled_rpc_effect_releases_the_exclusive_phase',
    'host_cache::owner::retention::snapshot_provenance_tests::previous_write_cannot_certify_new_generation_or_another_inode',
    'host_cache::recovery_inspection::collection::tests::duplicate_candidates_consume_the_occurrence_budget',
    'host_cache::recovery_inspection::collection::tests::native_names_reject_aliases_and_wrong_widths',
    'host_cache::recovery_inspection::tests::actual_metadata_pack_requires_the_exact_original_manifest_record_range',
    'host_cache::recovery_inspection::tests::actual_pack_bytes_derive_exact_index_but_corrupt_body_never_does',
    'host_cache::recovery_inspection::tests::compressed_pack_dictionary_respects_remaining_plaintext_budget',
    'host_cache::recovery_inspection::tests::compressed_standalone_plaintext_is_bounded_before_decode',
    'host_cache::recovery_inspection::tests::configured_custody_rejects_rebased_owner_and_group',
    'host_cache::recovery_inspection::tests::configured_directory_mode_is_not_rebased_to_current_metadata',
    'host_cache::recovery_inspection::tests::equal_sized_in_place_change_fails_actual_encoded_hash_recheck',
    'host_cache::recovery_inspection::tests::equal_sized_path_replacement_does_not_match_retained_inode',
    'host_cache::recovery_inspection::tests::oversized_actual_inode_is_rejected_before_encoded_allocation',
    'host_cache::recovery_inspection::tests::positioned_recovery_read_preserves_the_actual_open_description_cursor',
    'host_cache::recovery_inspection::tests::retained_manifest_inspection_requires_the_complete_manifest_key',
    'host_cache::recovery_inspection::tests::retained_manifest_plaintext_limit_is_checked_before_any_body_read',
    'host_cache::recovery_inspection::tests::retained_manifest_plaintext_uses_positioned_reads_without_changing_shared_cursor',
    'host_cache::recovery_inspection::tests::retained_manifest_residences_preserve_order_offsets_and_manifest_identity',
    'host_cache::recovery_inspection::tests::retained_manifest_verifies_full_plaintext_and_preserves_its_metadata_identity',
    'host_cache::recovery_inspection::tests::structural_pack_allocation_is_bounded_before_decoded_records',
    'host_cache::recovery_inspection::tests::unresolved_verification_failure_preserves_its_typed_source',
    'publisher_local::client::recovery_manifest::tests::candidate_comparison_requires_the_complete_registered_key',
    'publisher_local::client::recovery_manifest::tests::retained_claim_comparison_rejects_other_domains_and_content',
)


PACKAGE_PATHS = {
    "terrane-format": "terrane/sdk/terrane-format",
    "terrane-sdk": "terrane/sdk/terrane-sdk",
    "terrane-linux": "terrane/linux/terrane-linux",
    "terrane-cli": "terrane/cli/terrane-cli",
    "aos-terrane-integration": "terrane/integration/aos-terrane-integration",
}


def unit_inventory(output):
    """Parses the complete real libtest inventory, rejecting unknown line types."""
    lines = [line for line in output.splitlines() if line]
    shared.require(lines and re.fullmatch(r"\d+ tests?, 0 benchmarks?", lines[-1]),
                   "missing complete FS unit inventory summary")
    names = [line.removesuffix(": test") for line in lines[:-1]]
    shared.require(all(line.endswith(": test") for line in lines[:-1])
                   and len(names) == len(set(names)) and 0 < len(names) <= 4096
                   and int(lines[-1].split()[0]) == len(names), "invalid FS unit inventory")
    selected = sorted(name for name in names if name.startswith(UNIT_PREFIXES))
    shared.require(selected == sorted(UNIT_TESTS) and len(selected) == len(UNIT_TESTS),
                   "FS unit module-prefix inventory changed")
    return sorted(names)


def source_unit_inventory(workspace):
    """Checks the retained selection against all test declarations in its scope."""
    source_roots = [workspace / "terrane/linux/terrane-linux/src/host_cache/owner",
                    workspace / "terrane/linux/terrane-linux/src/host_cache/recovery_inspection",
                    workspace / "terrane/linux/terrane-linux/src/publisher_local/client/recovery_manifest.rs"]
    declared = []
    for root in source_roots:
        for path in sorted(root.rglob("*.rs")) if root.is_dir() else [root]:
            declared.extend(re.findall(r"#\[test\]\s*fn\s+(\w+)\s*\(", path.read_text()))
    shared.require(len(declared) == len(UNIT_TESTS)
                   and sorted(declared) == sorted(name.rsplit("::", 1)[1] for name in UNIT_TESTS),
                   "source FS unit declarations differ from retained selection")


def unit_artifact(workspace, temporary, target, packages):
    """Selects the actual FS libtest ELF from its explicit test-profile build."""
    profile = tomllib.loads((workspace / "Cargo.toml").read_text()).get("profile", {}).get("test")
    shared.require(profile == {"debug": 0, "opt-level": "s"}, "unreviewed FS test profile")
    records = [json.loads(line) for line in (temporary / f"host-cache-{UNIT_NAME}.jsonl").read_text().splitlines()]
    package = [item for item in packages if pathlib.Path(item["manifest_path"]) == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
    candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                  and item.get("target", {}).get("name") == "terrane_linux" and item.get("executable")]
    shared.require(len(package) == len(candidates) == 1, "ambiguous FS libtest artifact")
    artifact = candidates[0]
    targets = [item for item in package[0]["targets"] if item["name"] == "terrane_linux" and item["kind"] == ["lib"]]
    executable = pathlib.Path(artifact["executable"])
    shared.require(len(targets) == 1 and artifact["target"] == targets[0]
                   and artifact["package_id"] == package[0]["id"] and package[0]["name"] == "terrane-linux"
                   and artifact["target"]["crate_types"] == ["lib"]
                   and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/src/lib.rs"
                   and artifact["profile"] == UNIT_PROFILE
                   and sorted(artifact["features"]) == ["native-test-fixtures", "tokio"]
                   and str(executable) in artifact["filenames"]
                   and executable.is_file() and os.access(executable, os.X_OK)
                   and executable.resolve().is_relative_to(target.resolve())
                   and executable.read_bytes().startswith(b"\x7fELF"), "FS libtest source/profile/ELF mismatch")
    source_unit_inventory(workspace)
    return artifact, executable, digest(executable)


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
        package = [item for item in packages if pathlib.Path(item["manifest_path"]) == workspace / PACKAGE_PATHS[crate] / "Cargo.toml"]
        candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                      and item.get("target", {}).get("name") == name and item.get("executable")]
        shared.require(len(package) == len(candidates) == 1, f"ambiguous cache proof artifact: {name}")
        artifact = candidates[0]
        targets = [item for item in package[0]["targets"] if item["name"] == name and item["kind"] == [kind]]
        executable = pathlib.Path(artifact["executable"])
        shared.require(len(targets) == 1 and artifact["target"] == targets[0]
                       and artifact["package_id"] == package[0]["id"] and package[0]["name"] == crate
                       and artifact["target"]["crate_types"] == ["bin"]
                       and pathlib.Path(artifact["target"]["src_path"]) == workspace / PACKAGE_PATHS[crate] / source
                       and artifact["profile"] == PROFILE and sorted(artifact["features"]) == features
                       and str(executable) in artifact["filenames"]
                       and executable.is_file() and os.access(executable, os.X_OK)
                       and executable.resolve().is_relative_to(target.resolve()),
                       f"cache proof source/target/profile/features mismatch: {name}")
        shared.require(executable.read_bytes().startswith(b"\x7fELF"), f"non-ELF artifact: {name}")
        result[name] = (artifact, executable, digest(executable))
    result[UNIT_NAME] = unit_artifact(workspace, temporary, target, packages)
    return result


def cargo_directories(name, executable, temporary, target, workspace):
    """Captures a genuine Cargo launch without executing any role entry point."""
    target_lib = pathlib.Path((temporary / "host-cache-target-libdir").read_text().strip())
    shared.require(target_lib.is_dir() and target_lib.resolve().is_relative_to("/nix/store"), "untrusted target library directory")
    capture = temporary / f"host-cache-{name}-library-path"
    working = temporary / f"host-cache-{name}-working-directory"
    runner = temporary / f"host-cache-{name}-runner"
    is_unit = name == UNIT_NAME
    expected_argument = "--list" if is_unit else "--discover"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = ' + expected_argument + ' ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(working)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_lib.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    with (temporary / f"host-cache-{name}-discovery.log").open("w") as log:
        command = (["cargo", "test", "--frozen", "--offline", "-p", "terrane-linux",
                    "--features", "native-test-fixtures", "--lib", "--", "--list"] if is_unit
                   else ["cargo", "run", *flags(name), "--", "--discover"])
        subprocess.run(command, env=environment,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    text = capture.read_text()
    shared.require(text.endswith("\n") and text.count("\n") == 1 and text.strip(), "missing Cargo launch environment")
    expected_cwd = workspace / "terrane/linux/terrane-linux" if is_unit else workspace
    shared.require(working.read_text() == str(expected_cwd) + "\n", "Cargo launch working-directory mismatch")
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
    for name in ["host-cache-proof.nix", "host_cache_image.py", "host_cache_vm.py", "manifest_publication_vm.py", "source_cleanup_vm.py", "admission_cache_vm.py", "native_sdk_test_image.py"]:
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
    supervisor_helpers = {}
    for helper_name in ["manifest_publication_vm.py", "source_cleanup_vm.py", "admission_cache_vm.py"]:
        helper_source = source / "tests/terrane" / helper_name
        helper_installed = output / "share" / helper_name
        shutil.copy2(helper_source, helper_installed)
        shared.require(helper_installed.read_bytes() == helper_source.read_bytes(), "installed supervisor helper differs from source")
        supervisor_helpers[helper_name] = {"source_path": "tests/terrane/" + helper_name,
                                          "installed_path": "share/" + helper_name, "sha256": digest(helper_installed)}
        checksums.append(f"{digest(helper_installed)}  share/{helper_name}\n")

    library_path = ":".join(map(str, [output / "lib", *store_paths]))
    listed = subprocess.run([str(output / "bin/host_cache_fixture"), "--list"],
                            env=dict(os.environ, LD_LIBRARY_PATH=library_path), check=True,
                            text=True, capture_output=True).stdout.splitlines()
    expected = ["host-cache:" + name for name in [
        "prepare", "empty", "refuse", "late-refuse", "cancel", "edquot", "hold", "start-refuse",
        "admit-chunk", "admit-metadata", "admit-cancel", "cache-admission-handoff", "dictionary-custody",
        "seed-manifest", "seed-bad-manifest", "seed-unsealed-manifest",
        "seed-unsealed-writable-manifest", "seed-truncated-manifest", "seed-writable-manifest",
        "recover-manifest", "refuse-manifest", "refuse-unsealed-manifest",
        "refuse-unsealed-writable-manifest", "refuse-truncated-manifest", "recover-writable-manifest",
        "publisher-confinement", "publisher-reject-descriptor", "publisher-reject-stdio",
        "seed-mixed-manifest", "seed-mixed-bad-manifest",
        "recover-mixed-manifest", "refuse-mixed-manifest",
        "consumer-leases", "publish-inline", "publish-inline-cancel", "publish-inline-transfer",
        "publish-inline-transfer-cancel", "publish-inline-transfer-conflict",
        "retain-running", "retain-running-cancel",
        "publish-manifest", "publish-manifest-cancel", "publish-manifest-bad-whole",
        "publish-manifest-dictionary",
        "publish-manifest-reuse",
        "publish-manifest-reuse-bad-whole",
        "source-cleanup", "source-cleanup-early",
    ]]
    shared.require(listed == expected, "cache fixture exact selector inventory mismatch")
    unit_elf = output / "bin" / UNIT_NAME
    unit_hash = digest(unit_elf)
    full_units = unit_inventory(subprocess.run([str(unit_elf), "--list"],
                               env=dict(os.environ, LD_LIBRARY_PATH=library_path),
                               cwd=workspace / "terrane/linux/terrane-linux", check=True, text=True,
                               capture_output=True).stdout)
    shared.require(digest(unit_elf) == unit_hash, "unit discovery changed installed FS ELF")
    unit_identity = {"full_inventory": full_units, "selected_inventory": sorted(UNIT_TESTS),
                     "prefixes": list(UNIT_PREFIXES), "working_directory": "crates/terrane/linux/terrane-linux",
                     "profile": UNIT_PROFILE, "guest_uid": 842, "guest_gid": 842}
    identity = {"schema_version": 1, "source": str(source), "artifacts": identities,
                "input_sha256": source_hashes, "selectors": listed, "supervisor": supervisor_identity,
                "supervisor_helpers": supervisor_helpers,
                "runtime_library_path": library_path, "native_cases_executed": [], "unit_tests": unit_identity}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/runtime-library-path").write_text(library_path + "\n")
    (output / "share/elf-sha256sum").write_text("".join(checksums))
    shutil.copy2(temporary / "host-cache-packages.json", output / "share/host-cache-packages.json")


if __name__ == "__main__":
    main()

"""Executes every original surface-gate selector in an unprivileged ext4 guest."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile


SUITES = {
    "interface": [
        (
            "surface_contract",
            "native_host_configuration_preserves_explicit_runtime_inputs",
        ),
        (
            "surface_contract",
            "native_host_configuration_rejects_missing_or_ambiguous_operator_inputs",
        ),
        (
            "surface_contract",
            "shared_host_configuration_preserves_requested_policy_without_runtime_claims",
        ),
        (
            "surface_contract",
            "shared_role_configuration_requires_explicit_invocation_selection",
        ),
        (
            "surface_contract",
            "registry_cannot_claim_uncompiled_or_runtime_loaded_surfaces",
        ),
        (
            "surface_contract",
            "exposures_preserve_order_and_reject_partial_configuration",
        ),
        (
            "surface_contract",
            "token_references_reject_inline_credentials_and_invalid_locators",
        ),
        (
            "surface_runtime",
            "preparation_refuses_entire_list_before_any_endpoint_starts",
        ),
        (
            "surface_runtime",
            "prepared_snapshots_recheck_current_authority_before_startup",
        ),
        (
            "surface_lifecycle_contract",
            "external_surface_owns_real_lifecycle_without_sdk_constructor_or_registration",
        ),
        (
            "configured_local_repository",
            "configured_local_reopen_prepares_and_starts_actual_read_only_sdk",
        ),
        (
            "configured_local_repository",
            "configured_local_reopen_never_substitutes_instance_token_for_exposure",
        ),
        (
            "configured_local_repository",
            "configured_local_reopen_rejects_unsupported_stores_and_nonserve_roles",
        ),
        (
            "configured_local_repository",
            "configured_local_reopen_requires_original_trust_and_validated_timing",
        ),
        (
            "configured_local_repository",
            "configured_local_reopen_preserves_signed_current_acl_denial",
        ),
        (
            "configured_local_repository",
            "configured_read_cache_preserves_original_authority_and_refuses_writes",
        ),
        (
            "configured_local_repository",
            "configured_complete_content_driver_preserves_authority_and_is_not_bypassed",
        ),
        (
            "configured_local_repository",
            "signed_storage_policy_refuses_before_body_reads_and_external_preparation",
        ),
    ],
    "commit-path": [
        (
            "surface_runtime",
            "readonly_sdk_refuses_writer_mode_before_any_endpoint_or_mutation",
        ),
    ],
    "schema": [
        (
            "surface_contract",
            "metadata_schema_checks_root_types_properties_and_forbidden_paths",
        ),
        (
            "surface_contract",
            "schemas_check_entry_kinds_attributes_root_and_forbidden_matches",
        ),
        (
            "surface_contract",
            "schema_collections_allow_empty_matches_but_literal_entries_establish_existence",
        ),
        (
            "surface_contract",
            "malformed_schema_patterns_fail_independently_of_tree_matches",
        ),
        (
            "surface_runtime",
            "schema_refusal_precedes_sdk_directory_creation",
        ),
        (
            "native-sdk",
            "repository::read::schema_tests::schema_metadata_reads_never_fetch_plaintext_chunks",
        ),
    ],
    "status": [
        (
            "surface_runtime",
            "prepared_snapshots_keep_validated_commit_and_report_complete_status",
        ),
        (
            "local_sdk",
            "lifecycle::sdk_checkout_public_api_lifecycle_preserves_completed_directory",
        ),
    ],
}


def check_identity():
    """Requires the guest's original unprivileged process boundary."""
    assert os.getuid() == os.geteuid() == 840
    assert os.getgid() == os.getegid() == 840 and os.getgroups() == []
    status = dict(line.split(":", 1) for line in Path("/proc/self/status")
                  .read_text().splitlines() if ":" in line)
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        assert int(status[name].strip(), 16) == 0, name
    assert status["NoNewPrivs"].strip() == "1"


def main():
    """Verifies retained Cargo artifacts before exact, nonignored execution."""
    sys.dont_write_bytecode = True
    image, native_image, source = map(Path, sys.argv[1:4])
    suite = sys.argv[4]
    cases = SUITES[suite]
    check_identity()
    storage = Path(os.environ["TMPDIR"])
    filesystem = subprocess.check_output([
        "findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(storage),
    ], text=True).strip()
    assert filesystem == "ext4"
    os.chdir(source / "crates")

    helpers = runpy.run_path(str(source / "tests/terrane/surface_test_image.py"))
    native = helpers["native_helper"](str(source / "tests/terrane/native_sdk_test_image.py"))
    verify_surface = helpers["verify_image"]
    verify_surface(image, source / "crates", source, native)
    verify_native = None
    if suite == "schema":
        verify_native = runpy.run_path(str(source / "tests/terrane/local_collection_vm.py"))["verify_image"]
        verify_native(source, native_image)

    check_output = runpy.run_path(str(source / "tests/terrane/check_native_gate.py"))["check_output"]
    binaries = {}
    for target in dict.fromkeys(target for target, _ in cases):
        directory = native_image if target == "native-sdk" else image / "targets" / target
        binary = directory / "bin/terrane-native-sdk-tests"
        inventory = subprocess.run([str(binary), "--list"], check=True, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
        required = [case for selected, case in cases if selected == target]
        check_output("inventory", inventory.stdout, required)
        for case in required:
            assert inventory.stdout.splitlines().count(case + ": test") == 1, case
        binaries[target] = {
            "command": str(binary),
            "sha256": hashlib.sha256((directory / "libexec/terrane-native-sdk-tests").read_bytes()).hexdigest(),
        }

    for target, case in cases:
        with tempfile.TemporaryDirectory(prefix="surface-case-", dir=storage) as directory:
            result = subprocess.run([
                binaries[target]["command"], case, "--exact", "--test-threads=1",
            ], env=dict(os.environ, TMPDIR=directory), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            print(result.stdout, end="", flush=True)
            result.check_returncode()
            check_output("execution", result.stdout, [case])
            assert re.findall(r"^test (.+) \.\.\. ok$", result.stdout, re.MULTILINE) == [case]
            assert len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;",
                                  result.stdout, re.MULTILINE)) == 1

    check_identity()
    verify_surface(image, source / "crates", source, native)
    if verify_native is not None:
        assert verify_native(source, native_image) == binaries["native-sdk"]["sha256"]
    print("SURFACE_CONTRACT_PROOF " + json.dumps({
        "suite": suite, "source": str(source), "image": str(image), "cases": cases,
        "uid": os.getuid(), "gid": os.getgid(), "capabilities": 0,
        "no_new_privileges": True, "filesystem": filesystem, "binaries": binaries,
    }, sort_keys=True), flush=True)
    print(f"PASS complete surface {suite} selectors execute in the original UID-840 ext4 guest",
          flush=True)


if __name__ == "__main__":
    main()

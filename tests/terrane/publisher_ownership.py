"""Checks the immutable Cargo inputs behind ARCH-8's native prerequisites."""

import hashlib
import json
import pathlib
import re
import sys

SOCKET_CASES = {
    "kernel_peer_credentials_cannot_be_claimed_in_packet",
    "configured_domain_selection_has_no_fallback",
    "real_seqpacket_roundtrip_requires_response_correlation",
    "duplicate_active_request_is_rejected_before_dispatch",
    "unsolicited_and_mismatched_responses_are_rejected",
    "oversized_payload_and_excess_rights_are_rejected",
    "received_rights_are_close_on_exec_and_writable_sources_fail",
    "rejected_rights_do_not_accumulate_descriptors",
    "ancillary_truncation_and_unregistered_credentials_are_rejected",
}
NATIVE_SOCKET_CASES = {
    "retained_socket_chmod_sets_exact_mode_without_changing_inode_or_group",
    "replaced_socket_name_is_rejected_without_changing_either_inode",
    "socket_chmod_rejects_wrong_type_and_owner_before_mutation",
}
PROTOCOL_CASES = {
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
}
TRANSPORT_TARGETS = {
    "terrane_fs": SOCKET_CASES | NATIVE_SOCKET_CASES,
    "publisher_local_protocol": PROTOCOL_CASES,
    "publisher_local_vm": {"publisher_local_multuid_vm", "publisher_local_vm_role"},
    "publisher_local_native": {"publisher_local_native_role", "publisher_local_native_lifecycle_vm"},
}


def require(condition, message):
    """Refuses incomplete or mismatched component evidence."""
    if not condition:
        raise SystemExit(message)


def sha256(path):
    """Hashes actual immutable source or installed artifact bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_inputs(image, source, helpers):
    """Compares every crate input and the complete proof-helper inventory."""
    identity = json.loads((image / "share/identity.json").read_text())
    expected = {path.relative_to(source / "crates").as_posix(): sha256(path)
                for path in sorted((source / "crates").rglob("*"))
                if path.is_file() and path.relative_to(source / "crates").as_posix()
                != ".cargo/config.toml"}
    expected.update({"tests/terrane/" + name: sha256(source / "tests/terrane" / name)
                     for name in helpers})
    require(identity.get("schema_version") == 1 and identity.get("source") == str(source)
            and identity.get("input_sha256") == expected,
            "publisher ownership proof differs from the current complete source")
    return identity


def check_transport(image, source):
    """Checks retained original ELF bytes and every portable execution record."""
    identity = check_inputs(image, source, [
        "publisher_local_proof.py", "native_sdk_test_image.py",
        "publisher-local-proof.nix", "native_socket_units.bash",
    ])
    artifacts = identity.get("artifacts", {})
    require(set(artifacts) == {*TRANSPORT_TARGETS, "publication_fixture"},
            "incomplete publisher transport artifact inventory")
    require(identity.get("requested_features") == ["native-test-fixtures"],
            "publisher transport requested features changed")
    for name, artifact in artifacts.items():
        is_test = name != "publication_fixture"
        profile = artifact.get("profile", {})
        target = artifact.get("target", {})
        kind = ["lib"] if name == "terrane_fs" else ["test"] if is_test else ["example"]
        require(artifact.get("features") == ["native-test-fixtures", "tokio"]
                and target.get("name") == name and target.get("kind") == kind
                and target.get("crate_types") == (["lib"] if name == "terrane_fs" else ["bin"])
                and profile.get("test") is is_test
                and profile.get("opt_level") == ("s" if is_test else "0")
                and profile.get("debuginfo") == (0 if is_test else 2)
                and profile.get("debug_assertions") is True
                and sha256(image / "libexec" / name) == artifact.get("executable_sha256"),
                "publisher transport source/profile/ELF mismatch: " + name)

    libraries = identity.get("copied_runtime_libraries", {})
    require(libraries and set(libraries) == {path.name for path in (image / "lib").iterdir()},
            "publisher transport runtime inventory mismatch")
    for name, digest in libraries.items():
        require(pathlib.Path(name).name == name and sha256(image / "lib" / name) == digest,
                "publisher transport runtime bytes changed")

    evidence = identity.get("tests", {})
    require(set(evidence) == {*TRANSPORT_TARGETS, "fresh-process-fixture"},
            "publisher transport execution inventory mismatch")
    for name, inventory in TRANSPORT_TARGETS.items():
        group = evidence[name]
        require(group.get("inventory") == sorted(inventory),
                "publisher transport selected tests changed: " + name)
        executed = group.get("executed", [])
        cases = SOCKET_CASES if name == "terrane_fs" else PROTOCOL_CASES if name == "publisher_local_protocol" else set()
        require([record.get("case") for record in executed] == sorted(cases),
                "publisher transport omitted or duplicated a portable case: " + name)
        for record in executed:
            prefix = "publisher_local::socket::tests::" if name == "terrane_fs" else ""
            require(len(re.findall(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$",
                                   record["stdout"])) == 1
                    and f"test {prefix}{record['case']} ... ok" in record["stdout"],
                    "publisher transport did not execute the original selected case")
    require(identity.get("native_socket_tests") == [
        "publisher_local::socket::tests::" + name for name in sorted(NATIVE_SOCKET_CASES)
    ], "publisher transport native socket cases changed")
    require(evidence["fresh-process-fixture"] == {
        "inventory": ["transport:native-publisher", "transport:native-client"], "executed": [],
    }, "publisher transport fresh-process selectors changed")
    return identity


def main():
    """Qualifies source identity after all real native prerequisites succeed."""
    require(len(sys.argv) == 4, "expected transport image, cache image and source")
    transport, cache, source = map(pathlib.Path, sys.argv[1:])
    transport_identity = check_transport(transport, source)
    cache_identity = check_inputs(cache, source, [
        "host-cache-proof.nix", "host_cache_image.py", "host_cache_vm.py",
        "manifest_publication_vm.py", "source_cleanup_vm.py", "native_sdk_test_image.py",
    ])
    print(json.dumps({
        "requirement": "ARCH-8", "source": str(source),
        "transport_image": str(transport), "cache_image": str(cache),
        "transport_inputs_verified": len(transport_identity["input_sha256"]),
        "cache_inputs_verified": len(cache_identity["input_sha256"]),
        "portable_cases_verified": len(SOCKET_CASES) + len(PROTOCOL_CASES),
        "transport_ELFs_verified": len(transport_identity["artifacts"]),
        "scope": "Native prerequisites qualify sole-writer custody; full host readiness is separate.",
    }, indent=2))


if __name__ == "__main__":
    main()

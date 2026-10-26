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
    "explicit_retirement_removes_original_name_and_allows_fresh_binding",
    "retirement_refuses_replacement_without_removing_either_inode",
    "retirement_uses_retained_parent_after_ancestor_replacement",
    "ordinary_drop_preserves_name_for_failed_startup_diagnosis",
    "retirement_refuses_newly_writable_parent_without_removing_socket",
}
PROTOCOL_CASES = {
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
}
TRANSPORT_TARGETS = {
    "terrane_linux": SOCKET_CASES | NATIVE_SOCKET_CASES,
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
    require(identity.get("schema_version") == 1 and identity.get("source") == str(source),
            "publisher ownership proof has another schema or immutable source")
    actual = identity.get("input_sha256")
    require(isinstance(actual, dict), "publisher ownership input inventory unavailable")
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    changed = sorted(name for name in expected.keys() & actual.keys()
                     if expected[name] != actual[name])
    require(actual == expected,
            "publisher ownership proof differs from the current complete source: "
            f"missing={missing}, unexpected={unexpected}, changed={changed}")
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
        kind = ["lib"] if name == "terrane_linux" else ["test"] if is_test else ["example"]
        require(artifact.get("features") == ["native-test-fixtures", "tokio"]
                and target.get("name") == name and target.get("kind") == kind
                and target.get("crate_types") == (["lib"] if name == "terrane_linux" else ["bin"])
                and profile.get("test") is is_test
                and profile.get("opt_level") == ("s" if is_test else "0")
                and profile.get("debuginfo") == (0 if is_test else 2)
                and profile.get("debug_assertions") is True
                and sha256(image / "libexec" / name) == artifact.get("executable_sha256"),
                "publisher transport source/profile/ELF mismatch: " + name)

    libraries = identity.get("copied_runtime_libraries", {})
    require(isinstance(libraries, dict)
            and set(libraries) == {path.name for path in (image / "lib").iterdir()},
            "publisher transport runtime inventory mismatch")
    for name, digest in libraries.items():
        require(pathlib.Path(name).name == name and sha256(image / "lib" / name) == digest,
                "publisher transport runtime bytes changed")

    # Static Rust linkage may require no copied target libraries. Resolve every
    # actual DT_NEEDED edge instead of using a nonempty copy list as evidence.
    # Store dependencies remain immutable AOS inputs; no host fallback is used.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "tests/terrane"))
    from native_sdk_test_image import runtime_closure

    directories = [pathlib.Path(value) for value in identity["runtime_library_path"].split(":")]
    require(directories and directories[0] == image / "lib"
            and all(path.is_absolute() and path.resolve().is_relative_to("/nix/store")
                    for path in directories), "publisher transport runtime search escaped the store")
    reached = {}
    for name in artifacts:
        copied, stores = runtime_closure(image / "libexec" / name, directories, image)
        require(set(stores) <= set(directories), "publisher transport has an undeclared runtime search")
        for library, path in copied.items():
            require(sha256(path) == libraries.get(library),
                    "publisher transport resolved another copied runtime library")
            reached[library] = sha256(path)
    require(reached == libraries, "publisher transport retained an unreachable runtime library")

    evidence = identity.get("tests", {})
    require(set(evidence) == {*TRANSPORT_TARGETS, "fresh-process-fixture"},
            "publisher transport execution inventory mismatch")
    for name, inventory in TRANSPORT_TARGETS.items():
        group = evidence[name]
        require(group.get("inventory") == sorted(inventory),
                "publisher transport selected tests changed: " + name)
        executed = group.get("executed", [])
        cases = PROTOCOL_CASES if name == "publisher_local_protocol" else set()
        require([record.get("case") for record in executed] == sorted(cases),
                "publisher transport omitted or duplicated a portable case: " + name)
        for record in executed:
            prefix = "publisher_local::socket::tests::" if name == "terrane_linux" else ""
            require(len(re.findall(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$",
                                   record["stdout"])) == 1
                    and f"test {prefix}{record['case']} ... ok" in record["stdout"],
                    "publisher transport did not execute the original selected case")
    require(identity.get("native_socket_tests") == [
        "publisher_local::socket::tests::" + name for name in sorted(SOCKET_CASES | NATIVE_SOCKET_CASES)
    ], "publisher transport native socket cases changed")
    require(evidence["fresh-process-fixture"] == {
        "inventory": ["transport:native-publisher", "transport:native-client"], "executed": [],
    }, "publisher transport fresh-process selectors changed")
    return identity


def check_socket_guest(proof, identity):
    """Requires exact nonignored execution and actual guest identity for all sockets."""
    require((proof / "result").read_text().strip() == "PASS",
            "publisher socket guest did not pass")
    serial = (proof / "serial.log").read_text()
    lines = serial.splitlines()
    require(lines.count("TEST_RESULT:PASS") == 1 and "TEST_RESULT:FAIL" not in serial,
            "publisher socket guest has no unique successful termination")
    require("Firecracker exiting successfully. exit_code=0" in serial,
            "publisher socket guest did not exit cleanly")
    cases = [line.removeprefix("SOCKET_UNIT_PASS ") for line in lines
             if line.startswith("SOCKET_UNIT_PASS ")]
    require(cases == identity["native_socket_tests"],
            "publisher socket guest omitted, repeated or reordered an original case")
    require(lines.count("SOCKET_UNIT_FILESYSTEM ext4") == 1
            and lines.count("SOCKET_UNIT_IDENTITY uid=841 gid=845 groups=none caps=zero nnp=1") == len(cases),
            "publisher socket guest lacks its actual ext4 and per-case identity controls")
    for case in cases:
        require(lines.count("test " + case + " ... ok") == 1,
                "publisher socket guest did not pass the original nonignored case: " + case)
    return {"output": str(proof), "serial_sha256": sha256(proof / "serial.log"),
            "executed": cases, "uid": 841, "gid": 845, "filesystem": "ext4"}


def main():
    """Qualifies source identity after all real native prerequisites succeed."""
    require(len(sys.argv) == 5, "expected transport image, cache image, source and native proof")
    transport, cache, source, native = map(pathlib.Path, sys.argv[1:])
    transport_identity = check_transport(transport, source)
    socket_guest = check_socket_guest(native, transport_identity)
    cache_identity = check_inputs(cache, source, [
        "host-cache-proof.nix", "host-cache-scenarios.nix", "host_cache_image.py", "host_cache_vm.py",
        "host_cache_temporaries_vm.py", "host_cache_index_recovery_vm.py", "host_cache_pending_recovery_vm.py", "host_cache_pending_packs_vm.py",
        "manifest_publication_vm.py", "source_cleanup_vm.py", "admission_cache_vm.py",
        "encoded_eviction_vm.py", "host_cache_encoded_recovery_vm.py",
        "shared_reextract_vm.py", "sealed_consumer_cold_vm.py",
        "native_feature_units_vm.py", "host_cache_mount_views_vm.py", "native_sdk_test_image.py",
    ])
    print(json.dumps({
        "requirement": "ARCH-8", "source": str(source),
        "transport_image": str(transport), "cache_image": str(cache),
        "transport_inputs_verified": len(transport_identity["input_sha256"]),
        "cache_inputs_verified": len(cache_identity["input_sha256"]),
        "portable_cases_verified": len(PROTOCOL_CASES),
        "socket_guest": socket_guest,
        "transport_ELFs_verified": len(transport_identity["artifacts"]),
        "scope": "Native prerequisites qualify sole-writer custody; full host readiness is separate.",
    }, indent=2))


if __name__ == "__main__":
    main()

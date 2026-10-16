# Local transport evidence only. These artifacts are prerequisites for broader
# registered gates; they do not qualify process sandboxing or native effects.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};

  image = sourceGateWithInputs {
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    nukeRefsKeep = [pkgs.terrane.src];
  } "publisher-local-proof-image" ''
    cd crates
    cargo test --frozen --offline -p terrane-fs --features tokio --lib \
      --test publisher_local_protocol --test publisher_local_vm \
      --no-run --message-format=json > "$TMPDIR/publisher-local-build.jsonl"

    python3 - "$TMPDIR/publisher-local-build.jsonl" "$out" "$src" <<'PY'
    import json
    import pathlib
    import shutil
    import subprocess
    import sys

    output = pathlib.Path(sys.argv[2])
    (output / "bin").mkdir()
    expected = {
        "terrane_fs": {
            "kernel_peer_credentials_cannot_be_claimed_in_packet",
            "real_seqpacket_roundtrip_requires_response_correlation",
            "duplicate_active_request_is_rejected_before_dispatch",
            "unsolicited_and_mismatched_responses_are_rejected",
            "oversized_payload_and_excess_rights_are_rejected",
            "received_rights_are_close_on_exec_and_writable_sources_fail",
            "rejected_rights_do_not_accumulate_descriptors",
            "ancillary_truncation_and_unregistered_credentials_are_rejected",
        },
        "publisher_local_protocol": {
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
    }
    artifacts = {}
    for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") == "compiler-artifact" and name in expected
                and event.get("profile", {}).get("test") and event.get("executable")):
            if name in artifacts:
                raise SystemExit("duplicate publisher-local test artifact")
            artifacts[name] = event["executable"]
    if set(artifacts) != set(expected):
        raise SystemExit("missing publisher-local test executable")

    evidence = {}
    for name, executable in artifacts.items():
        installed = output / "bin" / name
        shutil.copy2(executable, installed)
        listed = subprocess.run([str(installed), "--list", "--format", "terse"], check=True, text=True, capture_output=True).stdout
        prefix = "publisher_local::socket::tests::" if name == "terrane_fs" else ""
        actual = {line.removesuffix(": test").removeprefix(prefix) for line in listed.splitlines() if line.endswith(": test") and line.startswith(prefix)}
        if actual != expected[name]:
            raise SystemExit(f"publisher-local exact inventory mismatch: {name}: {actual}")
        evidence[name] = {"inventory": sorted(actual), "executed": []}
        if name == "publisher_local_vm":
            continue
        for case in sorted(actual):
            result = subprocess.run([str(installed), "--exact", prefix + case, "--nocapture"], check=True, text=True, capture_output=True)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                raise SystemExit(f"publisher-local test did not execute exactly once: {case}")
            evidence[name]["executed"].append({"case": case, "stdout": result.stdout, "stderr": result.stderr})
    (output / "evidence.json").write_text(json.dumps({"source": sys.argv[3], "features": ["tokio"], "tests": evidence}, indent=2) + "\n")
    PY
  '';

  multiUid = testing.mkVMTest {
    name = "terrane-publisher-local-multuid";
    memory = 512;
    rootfsDeps = [image pkgs.coreutils];
    testScript = ''
      set -eu
      mkdir -p /var/lib
      export TERRANE_PUBLISHER_VM=1
      ${image}/bin/publisher_local_vm --exact publisher_local_multuid_vm --ignored --nocapture
    '';
  };
in {
  inherit image multiUid;
}

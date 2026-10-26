"""Binds the public distribution-transport contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "loopback_http1_json_registers_every_mandatory_method",
    "loopback_http2_connect_and_grpc_preserve_protobuf_frames",
    "loopback_grpc_web_has_data_and_success_trailer",
    "tls13_serves_both_http_versions_and_refuses_tls12",
    "rejects_remote_plaintext_invalid_resources_and_malformed_identity",
    "whole_stream_deadline_releases_a_pending_response_source",
    "authentication::refuses_missing_malformed_duplicate_and_tampered_credentials_before_decode",
    "authentication::preserves_exact_verified_token_and_rechecks_live_expiry_and_key_retirement",
    "authentication::authenticates_server_and_client_streams_without_dispatching_invalid_calls",
    "authentication::anonymous_capabilities_is_explicit_and_never_hides_invalid_credentials",
    "authentication::preserves_attenuation_and_refuses_a_token_from_an_unconfigured_issuer",
    "presence::preserves_order_duplicates_and_maximum_batch",
    "presence::empty_and_refused_requests_never_connect",
    "presence::refuses_missing_or_extra_bitmap_bytes_without_partial_hints",
    "presence::ignores_unused_bits_but_preserves_each_requested_bit",
    "presence::retains_transport_bounds_and_whole_call_deadline",
    "negotiation::combines_all_stages_and_preserves_maximum_request_order",
    "negotiation::empty_and_invalid_inputs_never_connect",
    "negotiation::refuses_unsolicited_and_malformed_hints_without_partial_results",
    "negotiation::retains_transport_bounds_deadlines_and_unused_tail_bits",
    "references::retains_complete_record_until_independent_context_matches",
    "references::accepts_absence_and_exact_freshness_boundaries_as_peer_claims",
    "references::invalid_requests_and_call_limits_never_connect",
    "references::refuses_changed_names_invalid_values_and_exceeded_freshness",
    "references::preserves_record_message_transport_and_whole_call_bounds",
]


def require(condition, message):
    """Refuses incomplete compilation or execution evidence."""
    if not condition:
        raise SystemExit(message)


def captured(command, log):
    """Retains original diagnostics and bounds each selector by thirty seconds."""
    with log.open("w") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=30)
    text = log.read_text()
    sys.stdout.write(text)
    require(result.returncode == 0, "Distribution transport proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--test", "distribution_transport"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "distribution_transport"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous Distribution transport integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/distribution_transport.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "Distribution transport integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid Distribution transport test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "Distribution transport test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "Distribution transport case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "Distribution transport integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "Distribution transport source changed during execution")
    retained = output / "distribution-transport-test"
    shutil.copyfile(executable, retained)
    retained.chmod(0o755)
    require(hashlib.sha256(retained.read_bytes()).hexdigest() == digest,
            "retained Distribution transport integration artifact changed")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact, "executable_sha256": digest,
        "retained_executable": str(retained),
        "executed_cases": CASES, "scope": "Native HTTP/TLS binding, optional capability-header authentication and bounded membership, negotiation and whole-ref reception over real sockets; no repository authorization, actual ref freshness or durability claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

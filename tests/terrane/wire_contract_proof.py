"""Binds the public wire codec contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "status::outcome_table_has_exact_status_required_detail_and_retry_policy",
    "status::retry_minimum_preserves_subseconds_and_refuses_overflow",
    "status::fenced_outcomes_always_retain_fenced_state_and_never_enable_retry",
    "status::not_found_status_has_only_the_public_error_info_detail",
    "status::native_conversion_retains_error_info_and_every_required_protobuf_detail",
    "refs::complete_reflogs_keep_exact_expectations_and_ref_values",
    "refs::reflog_limits_timestamp_bounds_and_incomplete_candidates_are_rejected",
    "refs::whole_records_preserve_policy_home_and_candidate_through_wire_roundtrip",
    "refs::missing_or_inconsistent_summaries_never_replace_canonical_records",
    "refs::incoming_profile_and_commit_claims_cannot_select_the_verified_context",
    "refs::cas_requires_explicit_absence_or_a_complete_matching_expected_record",
    "refs::identical_summaries_keep_distinct_whole_record_cas_expectations",
    "refs::canonical_record_limits_and_malformed_cbor_fail_before_returning_a_record",
    "stable_field_numbers_preserve_complete_ref_records",
    "protojson_preserves_uint64_bytes_aliases_and_defaults",
    "unknown_wire_fields_and_open_enum_numbers_survive_roundtrip",
    "unknown_json_fields_are_ignored_and_null_is_unset",
    "oneof_frames_reject_ambiguous_json_and_keep_binary_tags",
    "well_known_time_types_use_canonical_protojson",
    "independent_descriptor_decoder_retains_service_shapes_and_record_fields",
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
    require(result.returncode == 0, "wire codec proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    reference = source / "docs/rfcs/0024-terrane/spec/reference/protocol.md"
    blocks = re.findall(r"```protobuf\n(.*?)```", reference.read_text(), re.S)[2:]
    require(len(blocks) == 5 and "package terrane.v1;" in blocks[0],
            "Distribution reference block inventory changed")
    schema = workspace / "terrane/sdk/terrane-sdk/proto/terrane.proto"
    def tokens(text):
        text = re.sub(r"//[^\n]*", "", text)
        return "".join(text.split())
    declared = schema.read_text()
    for imported in ["timestamp", "duration"]:
        statement = f'import "google/protobuf/{imported}.proto";'
        require(declared.count(statement) == 1, "missing or repeated well-known import")
        declared = declared.replace(statement, "")
    require(tokens(declared) == tokens("\n".join(blocks)),
            "compiled Distribution schema differs from the complete normative reference")
    require(schema.read_bytes() == (source / schema.relative_to(workspace.parent)).read_bytes(),
            "compiled schema differs from immutable source")
    compiler = Path(os.environ["PROTOC"])
    require(str(compiler).startswith("/nix/store/"), "protobuf compiler lacks an AOS store binding")
    compiler_version = subprocess.check_output([str(compiler), "--version"], text=True).strip()
    mode = os.environ.get("TERRANE_WIRE_NATIVE", "")
    require(mode in ["", "1"], "unknown wire qualification feature mode")
    native = mode == "1"
    features = ["--features", "tokio"] if native else ["--no-default-features"]
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               *features, "--test", "wire_contract"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "wire_contract"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous wire codec integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/wire_contract.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == (["default", "send", "std", "tokio"] if native else [])
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "wire codec integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid wire codec test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "wire codec test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "wire codec case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "wire codec integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "wire codec source changed during execution")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs,
        "reference_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
        "schema_sha256": hashlib.sha256(schema.read_bytes()).hexdigest(),
        "compiler": str(compiler), "compiler_version": compiler_version, "artifact": artifact, "executable_sha256": digest,
        "executed_cases": CASES, "native_status_serialization": native,
        "scope": "Generated encoding and classified status mapping; no service implementation or authorization claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

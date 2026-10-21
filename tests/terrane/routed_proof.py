"""Binds the public routed-store contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "cache_only::content_only_route_preserves_order_without_any_write_destination",
    "cache_only::content_only_route_never_converts_failed_or_unqueried_children_into_absence",
    "cache_only::content_only_route_rejects_authority_claims_empty_routes_and_invalid_resources",
    "routes_in_configured_order_and_preserves_exact_ranges",
    "corrupt_and_pending_children_fall_through_under_real_timers",
    "clones_share_open_circuits_and_one_scheduled_probe",
    "whole_request_deadline_never_attempts_a_later_child",
    "membership_queries_only_unresolved_identities_without_inventing_absence",
    "denial_is_terminal_and_upload_and_ref_operations_reach_only_authority",
    "rejects_two_authorities_missing_authority_and_invalid_bounds",
    "exhausted_reads_preserve_shortest_reported_retry_without_claiming_absence",
    "authority_failure_and_pending_upload_never_acknowledge_or_write_a_cache",
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
    require(result.returncode == 0, "routed proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--test", "routed_store"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "routed_store"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous routed integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/routed_store.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "routed integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid routed test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "routed test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "routed case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "routed integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "routed source changed during execution")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact, "executable_sha256": digest,
        "executed_cases": CASES, "scope": "Public routing combinator contract; no physical custody claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

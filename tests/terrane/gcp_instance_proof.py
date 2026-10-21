"""Binds the public gcp-instance-issuer contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "signed_full_identity_mints_only_the_assigned_instance_and_job",
    "signed_ci_identity_cannot_mint_baseline_or_other_change_writes",
    "changed_signatures_unknown_keys_and_unsupported_headers_are_denied",
    "signed_claims_cannot_select_another_project_instance_account_or_job",
    "signed_identity_times_are_checked_with_the_injected_clock",
    "unavailable_ambiguous_and_excessive_key_responses_never_mint",
    "complete_exchange_deadline_drops_a_pending_key_stream",
    "duplicate_assignments_and_invalid_trusted_configuration_are_rejected",
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
    require(result.returncode == 0, "GCP instance issuer proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--test", "gcp_instance_issuer"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "gcp_instance_issuer"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous GCP instance issuer integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/gcp_instance_issuer.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "GCP instance issuer integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid GCP instance issuer test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "GCP instance issuer test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "GCP instance issuer case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "GCP instance issuer integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "GCP instance issuer source changed during execution")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact, "executable_sha256": digest,
        "executed_cases": CASES, "scope": "Recorded GCE claims and actual RSA verification with bounded injected HTTPS key transport; no live Google probe or deployed endpoint claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

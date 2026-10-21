"""Binds the public workload-issuer contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "private_file_mints_exact_authenticated_workload_claims",
    "ci_change_credentials_allow_only_baseline_fork_and_assigned_branch_writes",
    "every_lifetime_bound_can_narrow_but_never_widen_issuance",
    "real_entropy_produces_distinct_tokens_and_offline_attenuation_keys",
    "expired_overflowing_and_discontinuous_time_refuse_issuance",
    "missing_identity_and_invalid_canonical_grants_never_issue_credentials",
    "key_file_rejects_links_inode_kinds_permissions_lengths_and_wrong_public_keys",
    "policy_paths_and_local_errors_fail_closed_without_disclosing_key_material",
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
    require(result.returncode == 0, "workload issuer proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--test", "workload_issuer"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "workload_issuer"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous workload issuer integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/workload_issuer.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "workload issuer integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid workload issuer test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "workload issuer test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "workload issuer case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "workload issuer integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "workload issuer source changed during execution")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact, "executable_sha256": digest,
        "executed_cases": CASES, "scope": "Native static-key workload issuance only; no remote authentication, GCP exchange or repository authorization claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

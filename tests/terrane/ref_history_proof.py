"""Checks actual guarded history reads and exact selected-history invariants."""

import hashlib
import json
import os
from pathlib import Path

from native_sdk_test_image import source_hashes
from sdk_contract_proof import captured, require, run_sdk_contract


CASES = [
    "committed_history_keeps_exact_order_provenance_and_reopened_head",
    "read_only_grants_can_read_history_but_other_branches_and_expiry_refuse",
    "absent_and_past_head_histories_are_empty_only_after_authorization",
    "malformed_and_nonbranch_names_cannot_open_history",
]

INVARIANTS = [
    "exact_horizon_excludes_append_first_candidates",
    "ordered_suffix_must_reach_the_exact_whole_head",
    "missing_duplicate_and_reordered_committed_sequences_refuse",
    "equal_commit_predecessor_with_a_different_selector_refuses",
    "legacy_history_checks_initial_absence_and_committed_predecessors",
    "selected_log_without_its_cas_expectation_refuses",
]


def main():
    """Binds all ten actual cases to their original Cargo artifacts and source."""
    run_sdk_contract(
        "ref_history", CASES,
        "Actual SDK committed history and current read authority; "
        "no deployed protocol, CLI or complete observability gate claim",
    )
    output = Path(os.environ["out"])
    workspace = Path.cwd()
    report = json.loads((output / "source-review.json").read_text())
    rows = [json.loads(line) for line in (output / "unit-build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_sdk"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous history invariant artifact")
    artifact = artifacts[0]
    target, profile = artifact["target"], artifact["profile"]
    require(target["kind"] == ["lib"] and target["crate_types"] == ["lib"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/src/lib.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "history invariant source, features or profile mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid history invariant executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    prefix = "repository::history::tests::"
    cases = [prefix + name for name in INVARIANTS]
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--lib"]
    inventory = captured(command + [prefix, "--", "--list", "--format", "terse"],
                         output / "invariant-inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines() if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(cases),
            "history invariant inventory changed")
    for name in cases:
        text = captured(command + [name, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (name + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + name + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "history invariant did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "history invariant executable changed")
    require(source_hashes(workspace, Path(os.environ["src"])) == report["input_sha256"],
            "history source changed during invariant execution")
    report["invariants"] = {"artifact": artifact, "executable_sha256": digest, "executed_cases": cases}
    (output / "source-review.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

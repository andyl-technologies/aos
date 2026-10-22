"""Binds root and scoped file metadata to their actual native SDK artifacts."""

import hashlib
import json
import os
from pathlib import Path

from native_sdk_test_image import source_hashes
from sdk_contract_proof import captured, require, run_sdk_contract


CASES = [
    "root_preparation_and_closing_check_request_no_content_bodies",
    "root_closing_refuses_a_policy_advance_and_fresh_historical_preparation_succeeds",
    "canonical_nodes_preserve_the_signed_target_without_any_content_read",
    "reopened_and_pinned_reads_preserve_the_selected_immutable_root",
    "exact_inventory_entry_and_path_limits_pass_and_each_underflow_refuses",
    "empty_roots_still_require_read_and_current_credentials",
    "surface_and_named_root_caveats_cannot_disclose_a_full_root",
    "raw_symlink_targets_survive_without_checkout_resolution",
    "a_denied_graft_descendant_refuses_the_entire_node_inventory",
]


POLICY_CASES = [
    "stable_current_policy_accepts_a_complete_historical_read",
    "a_policy_transition_between_paths_refuses_the_bulk_read",
    "returning_to_the_same_commit_does_not_hide_a_closing_head_change",
]


FILE_CASES = [
    "file_preparation_selects_exact_signed_metadata_without_content_reads",
    "closing_refuses_a_real_policy_advance_and_a_fresh_historical_read_succeeds",
    "a_root_scoped_token_prepares_a_file_without_disclosing_an_unrelated_graft",
    "manifest_file_preparation_requires_no_manifest_or_chunk_body_read",
    "non_files_invalid_paths_and_wrong_surfaces_never_prepare_a_handle",
]


def main():
    """Binds full-root disclosure and actual policy transitions to their artifacts."""
    output = Path(os.environ["out"])
    run_sdk_contract(
        "file_read", FILE_CASES,
        "Actual signed scoped file metadata without body reads; fresh same-whole-head "
        "closing authorization, with no kernel backing or exposure lease claim",
    )
    file_report = json.loads((output / "source-review.json").read_text())
    (output / "inventory.log").rename(output / "file-preparation-inventory.log")
    run_sdk_contract(
        "root_nodes", CASES,
        "Actual signed full-root metadata, per-path Read and provenance checks; "
        "no file bodies, live exposure lease, index custody or mount claim",
    )
    workspace = Path.cwd()
    report = json.loads((output / "source-review.json").read_text())
    require(file_report["source"] == report["source"]
            and file_report["input_sha256"] == report["input_sha256"],
            "file and root metadata artifacts have different immutable inputs")
    report["file_preparation"] = {
        key: file_report[key] for key in ["artifact", "executable_sha256", "executed_cases", "scope"]
    }
    rows = [json.loads(line) for line in (output / "unit-build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_sdk"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous root policy artifact")
    artifact = artifacts[0]
    target, profile = artifact["target"], artifact["profile"]
    require(target["kind"] == ["lib"] and target["crate_types"] == ["lib"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/src/lib.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk") + "#")
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "root policy artifact source, features or profile mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid root policy executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    prefix = "guard::read::path_batch::tests::"
    cases = [prefix + name for name in POLICY_CASES]
    inventory = captured([str(executable), prefix, "--list", "--format", "terse"],
                         output / "policy-inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines() if line.endswith(": test")]
    require(len(actual) == len(set(actual)) == len(cases) and set(actual) == set(cases),
            "root policy inventory changed")
    for name in cases:
        lines = captured([str(executable), name, "--exact", "--nocapture", "--test-threads=1"],
                         output / (name + ".log")).splitlines()
        require(lines.count("test " + name + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "root policy case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "root policy executable changed")
    require(source_hashes(workspace, Path(os.environ["src"])) == report["input_sha256"],
            "root policy source changed during execution")
    report["policy"] = {"artifact": artifact, "executable_sha256": digest, "executed_cases": cases}
    (output / "source-review.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

"""Binds structural metadata and inode policy tests to actual source and ELF bytes."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "nested_tree_has_sorted_paths_and_contiguous_direct_child_indices",
    "child_resume_skips_direct_indices_and_remains_exhausted_for_oversized_offsets",
    "content_kind_size_symlink_bytes_and_graft_governance_survive_roundtrip",
    "empty_tree_and_exact_compiler_bounds_are_supported",
    "compiler_rejects_missing_nondirectory_duplicate_and_invalid_paths",
    "every_truncation_and_hostile_header_offset_is_rejected",
    "forged_parent_child_and_arena_relationships_are_rejected",
    "arbitrary_short_inputs_and_single_byte_mutations_never_panic",
    "compiled::canonical_compilation_refuses_a_valid_index_with_an_unchanged_root_tag",
    "compiled::streaming_copy_and_verification_preserve_short_io_failures_and_exact_length",
    "metadata::canonical_tree_preserves_modes_unknown_fields_and_graft_properties",
    "metadata::hardlinks_share_checked_inodes_but_repeated_grafts_and_equal_content_do_not",
    "metadata::malformed_metadata_maps_modes_and_cursors_are_refused",
    "metadata::forged_link_runs_counts_and_canonical_entries_are_refused",
    "metadata::metadata_key_order_duplicate_names_and_old_format_are_refused",
    "trees::canonical_nested_grafts_compile_without_any_file_content_input",
    "trees::repeated_grafts_expand_at_distinct_paths_with_one_governing_root",
    "trees::absent_misbound_nonordinary_and_wrong_geometry_grafts_are_refused",
    "trees::expanded_entries_bytes_and_full_paths_obey_compiler_limits",
    "trees::maximum_graft_depth_is_supported_and_the_next_edge_is_refused",
    "trees::raw_nodes_compile_only_after_actual_identity_and_graft_validation",
    "trees::raw_nodes_check_internal_summaries_after_individual_hashes_match",
    "trees::raw_node_budget_charges_all_keys_before_decoding_or_expansion",
]
PREFIX = "structural_index::tests::"
INODE_PREFIX = "inode_policy::tests::"
INODE_CASES = [
    "internal_identity_is_independent_of_first_lookup_order",
    "full_table_preserves_old_numbers_and_canonical_link_counts",
    "metadata_refusal_consumes_no_number_or_existing_identity",
    "truncated_collision_cannot_alias_or_replace_a_retained_entry",
    "invalid_bounds_and_paths_fail_before_table_growth",
    "reserved_budget_refuses_before_allocation_and_keeps_number_assignment_lazy",
    "reserved_probe_chains_keep_collisions_and_full_table_refusals_distinct",
    "reserved_first_touch_and_checked_metadata_operations_allocate_nothing",
    "directory_pages_and_refusals_do_not_allocate_even_on_first_inode_touch",
]
METADATA_PREFIX = "fuse_metadata::tests::"
METADATA_CASES = [
    'lookup_and_getattr_preserve_recorded_fields_and_hardlink_identity',
    'root_and_symlink_replies_keep_kernel_root_separate_and_target_bytes_exact',
    'canonical_overrides_ignore_recorded_ownership_and_keep_explicit_timestamps',
    'refused_metadata_or_capacity_never_assigns_an_inode_or_changes_output',
    'negative_lookup_caches_absence_only_for_pinned_views_and_clears_payload',
]
DIRECTORY_PREFIX = "fuse_directory::tests::"
DIRECTORY_CASES = [
    "encodes_only_direct_children_with_exact_names_types_padding_and_parent",
    "resumes_one_complete_record_at_a_time_and_rewind_preserves_original_numbers",
    "raw_maximum_component_needs_one_complete_aligned_record_before_inode_assignment",
    "rejects_lazy_storage_absent_paths_and_non_directories_without_effects",
    "inode_exhaustion_never_writes_a_partial_record_or_recycles_a_number",
    "hard_link_names_share_one_presented_inode_but_equal_content_keeps_distinct_inodes",
]


def require(condition, message):
    """Rejects mismatched or incomplete execution evidence."""
    if not condition:
        raise SystemExit(message)


def main():
    """Checks one source-bound Linux artifact and four complete test inventories."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_linux"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous structural index test artifact")
    artifact = artifacts[0]
    profile = artifact["profile"]
    require(artifact["target"]["kind"] == ["lib"]
            and Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/src/lib.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/linux/terrane-linux") + "#")
            and artifact["features"] == ["surface-fuse"]
            and profile["test"] and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"],
            "structural index artifact source, features or profile mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid structural index test ELF")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    def captured(arguments, name):
        with (output / name).open("w") as log:
            result = subprocess.run([str(executable), *arguments], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=30)
        text = (output / name).read_text()
        sys.stdout.write(text)
        require(result.returncode == 0, "structural index selector failed")
        return text.splitlines()

    cases = []
    for prefix, names, label in [(PREFIX, CASES, "structural"),
                                 (INODE_PREFIX, INODE_CASES, "inode"),
                                 (DIRECTORY_PREFIX, DIRECTORY_CASES, "directory"),
                                 (METADATA_PREFIX, METADATA_CASES, "metadata")]:
        expected = [prefix + name for name in names]
        inventory = captured([prefix, "--list", "--format", "terse"], label + "-inventory.log")
        actual = [line.removesuffix(": test") for line in inventory if line.endswith(": test")]
        require(len(actual) == len(set(actual)) == len(expected) and set(actual) == set(expected),
                label + " inventory changed")
        cases.extend(expected)
    for case in cases:
        lines = captured([case, "--exact", "--nocapture", "--test-threads=1"], case + ".log")
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "structural index case did not execute once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "structural index test ELF changed")
    # Retain the exact executed bytes for independent audit. This is a test
    # artifact, not a relocated standalone application with a runtime launcher.
    retained = output / "artifacts/terrane-structural-tests.elf"
    retained.parent.mkdir()
    shutil.copyfile(executable, retained)
    retained.chmod(0o444)
    require(hashlib.sha256(retained.read_bytes()).hexdigest() == digest,
            "retained structural test ELF differs from executed bytes")
    require(source_hashes(workspace, source) == inputs, "structural index source changed")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact,
        "executable_sha256": digest, "executed_cases": cases,
        "retained_artifact": str(retained.relative_to(output)),
        "scope": "Structural codec, metadata reply encoders and bounded checked inode policy only; no sealed mapping, cache lease or FUSE worker authority",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

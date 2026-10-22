"""Binds complete root metadata disclosure to the actual native SDK artifact."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "canonical_nodes_preserve_the_signed_target_without_any_content_read",
    "reopened_and_pinned_reads_preserve_the_selected_immutable_root",
    "exact_inventory_entry_and_path_limits_pass_and_each_underflow_refuses",
    "empty_roots_still_require_read_and_current_credentials",
    "surface_and_named_root_caveats_cannot_disclose_a_full_root",
    "raw_symlink_targets_survive_without_checkout_resolution",
    "a_denied_graft_descendant_refuses_the_entire_node_inventory",
]


if __name__ == "__main__":
    run_sdk_contract(
        "root_nodes", CASES,
        "Actual signed full-root metadata, per-path Read and provenance checks; "
        "no file bodies, live exposure lease, index custody or mount claim",
    )

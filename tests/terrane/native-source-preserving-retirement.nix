{sourceGate}: let
  names = [
    "source_preserving_retirement_carries_complete_view_contexts_to_new_loss_generation"
    "cold_fork_after_source_preserving_retirement_reads_zero_tree_nodes"
    "expired_lease_source_drops_carry_without_reviving_witness_chunks"
    "changed_selected_source_original_or_interpretation_refuses_stale_carry"
    "removed_index_marked_member_prevents_source_preserving_retirement"
    "lineage_stage_or_native_sync_failure_never_acknowledges_partial_carry"
    "count_zero_source_carry_does_not_revive_unrelated_parent_chunks"
    "duration_source_carry_does_not_revive_expired_parent_chunks"
  ];
  selectors =
    map (name: "gc::runner::tests::source_carry::${name}") names
    ++ ["gc::runner::walk::tests::native::gc_roots_native_current_inventory_keeps_all_commit_classes_and_live_jobs"];
  runCases = import ./_native-cases.nix {
    label = "native-source-preserving-retirement";
    inherit selectors;
  };
in
  # A complete ordinary source walk and real retirement must precede cold reuse.
  sourceGate "native-source-preserving-retirement" ''
    ${runCases}
    printf 'PASS: nine exact native source-preserving retirement prerequisites\n' > "$out/result"
  ''

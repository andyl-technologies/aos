{sourceGate}: let
  selectors = [
    "indexing::tests::index_loader_loads_bound_hierarchical_graph_without_mutation"
    "indexing::tests::index_loader_preserves_physical_and_contextual_node_checks"
    "indexing::tests::index_loader_reports_missing_bindings_and_unavailable_evidence"
    "indexing::tests::index_loader_refuses_divergent_relationships_and_keeps_work_separate"
    "indexing::tests::load_source_reads_unbound_namespace_without_auxiliary_reads"
    "indexing::tests::load_source_preserves_shared_grafts_and_internal_physical_contexts"
    "indexing::tests::load_source_keeps_typed_source_failures_and_selected_revisions"
    "bucket::content::held_nodes::tests::held_node_reads_share_same_pack_data_and_require_once_only_fresh_close"
    "bucket::content::held_nodes::tests::held_node_reads_refuse_recaptured_selection_and_repeated_closing"
    "bucket::content::held_nodes::tests::held_node_data_survives_pack_removal_but_cannot_complete_its_read_scope"
    "bucket::content::held_nodes::tests::held_node_close_refuses_pack_overwrite_and_equal_byte_reincarnation"
    "bucket::content::held_nodes::tests::held_node_close_refuses_detached_index_and_catalog_reincarnation"
    "bucket::content::held_nodes::tests::held_node_close_refuses_changed_original_pack_ancestry"
    "bucket::content::held_nodes::tests::held_node_close_refuses_equal_child_bytes_under_reincarnated_parent"
    "bucket::content::held_nodes::tests::held_node_close_refuses_actual_selected_revision_change"
    "bucket::content::held_nodes::tests::held_node_close_refuses_selected_slot_and_guard_reincarnation"
    "bucket::content::held_nodes::tests::cancelled_native_pack_read_wakes_waiters_without_publishing_incomplete_data"
    "bucket::content::held_nodes::tests::cancelling_actual_closing_reads_cannot_complete_the_scope"
    "bucket::content::held_nodes::tests::actual_unchanged_native_deadline_expiry_refuses_node_scope_completion"
    "bucket::content::held_nodes::tests::shared_actual_node_bytes_cannot_supply_an_incompatible_auxiliary_role"
    "store::native_effect::publication::capture::predicate_tests::directory_link_growth_keeps_original_input_recipe_and_fresh_refusals"
    "store::native_effect::publication::capture::predicate_tests::differing_original_input_constraints_remain_distinct_and_fail_closed"
    "store::native_effect::publication::capture::predicate_tests::missing_input_stays_absent_after_predicate_coalescence"
  ];
in
  # Immutable loading and relationship verification precede current view checks.
  sourceGate "native-index-loading" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$out/discovery.log"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/discovery.log" '${builtins.toJSON selectors}'

    case_number=0
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      case_number=$((case_number + 1))
      case_log="$out/case-$case_number.log"
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$case_log" 2>&1; then
        cat "$case_log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$case_log" "[\"$test_name\"]"
    done
    printf 'PASS: twenty-three exact immutable index loading and physical input refusal cases\n' > "$out/result"
  ''

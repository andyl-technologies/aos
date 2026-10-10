# Qualifies canonical index contracts and their actual native publication paths.
# Memo replay/retention is owned by derivation-memo, not duplicated here.
{
  lib,
  sourceGate,
  ...
}: let
  coreTests = [
    "indexing::tests::owner_bindings_require_canonical_noninherited_root_values"
    "indexing::tests::executable_index_recipes_are_closed_and_legacy_recipes_remain_data"
    "indexing::tests::index_keys_roundtrip_exact_canonical_values_and_object_targets"
    "indexing::carrier_tests::contextual_carriers_preserve_object_targets_and_role_shapes"
    "indexing::carrier_tests::structural_index_names_do_not_become_value_inputs"
    "indexing::carrier_tests::gap_bindings_require_primary_root_placement_and_exact_wrapper"
    "indexing::evaluation_tests::hierarchical_index_matches_independent_source_occurrences"
    "indexing::evaluation_tests::verification_rejects_divergent_rows_routes_and_gaps"
    "indexing::evaluation_tests::role_contexts_preserve_shared_nodes_without_false_authority"
    "indexing::evaluation_tests::generated_missing_inline_coverage_is_independent_of_candidate_count"
    "indexing::evaluation_tests::hierarchical_local_keys_do_not_flatten_long_graft_paths"
    "indexing::evaluation_tests::conditional_sources_remain_incomplete_and_canonical_layers_are_indexed"
    "indexing::evaluation_tests::source_geometry_identities_and_registered_value_types_are_checked"
    "indexing::evaluation_tests::canonical_internal_routes_check_child_summaries_and_boundaries"
    "indexing::evaluation::layer_tests::layer_index_preserves_regular_file_rows_and_exact_graft_occurrences"
    "indexing::evaluation::layer_tests::layer_index_keeps_ordinary_identity_and_rejects_nonnamespace_contexts"
    "indexing::evaluation::layer_tests::layer_index_rejects_divergent_rows_and_owner_identity"
    "indexing::completion::tests::owner_completion_binds_independent_indexes_to_new_owner"
    "indexing::completion::tests::owner_completion_preserves_bindings_and_unchanged_descendants"
    "indexing::completion::tests::owner_completion_rebuilds_divergent_binding_without_changing_index_bytes"
    "indexing::completion::tests::owner_completion_refuses_invalid_sources_selections_and_auxiliary_closures"
    "indexing::completion::tests::owner_completion_forms_common_memo_only_after_binding_and_separates_work"
    "indexing::incremental::tests::source_discovery_preserves_local_hops_and_expands_changed_grafts"
    "indexing::incremental::tests::source_discovery_skips_equal_frontiers_and_reports_logical_changes"
    "indexing::incremental::tests::source_discovery_refuses_invalid_graphs_and_contexts"
    "indexing::incremental::tests::selected_source_lookups_ignore_growing_unrelated_graphs"
    "indexing::incremental::tests::selected_source_preparation_counts_reachable_storage_and_repeated_contexts"
    "indexing::incremental::tests::selected_source_binding_refuses_other_geometry_and_semantic_revisions"
    "indexing::incremental::lookup::tests::clones_share_one_flat_snapshot_without_generation_chains"
    "indexing::incremental::lookup::tests::lookup_counter_overflow_refuses_without_wrapping"
    "indexing::maintenance::tests::maintenance_matches_complete_independent_routes_and_logical_deltas"
    "indexing::maintenance::tests::maintenance_repeated_updates_retain_stable_storage_and_bounded_maps"
    "indexing::maintenance::tests::maintenance_batches_all_levels_and_conserves_real_boundary_work"
    "indexing::maintenance::tests::maintenance_refuses_invalid_relations_and_mismatched_update_bindings"
    "indexing::maintenance::tests::maintenance_separates_initial_rebuild_validation_and_export_work"
    "indexing::maintenance::update::publication_tests::publication_contains_only_reachable_new_emissions_and_discards_intermediate_roots"
    "indexing::maintenance::update::publication_tests::unchanged_update_publishes_no_bytes_while_full_verification_remains_available"
    "indexing::maintenance::update::publication_tests::initialization_exports_full_population_including_canonical_empty_root"
    "indexing::maintenance::update::publication_tests::emitted_identity_reused_from_old_closure_is_excluded"
    "indexing::maintenance::update::publication_tests::installation_refuses_new_root_without_its_emitted_bytes"
    "indexing::lookup::tests::candidate_ranges_match_independent_typed_rows_with_logarithmic_work"
    "indexing::lookup::tests::occurrence_walk_preserves_local_hops_gaps_and_sharing"
    "indexing::lookup::tests::lookup_preparation_refuses_divergent_data_and_separates_validation_work"
    "tree_builder::tests::tree_boundaries_empty_and_single_leaf"
    "tree_builder::tests::tree_history_independence_insert_remove"
    "tree_builder::tests::tree_boundaries_replay_every_fixture_level_and_summary"
    "tree_builder::tests::tree_boundaries_golden_leaf_identity"
    "tree_builder::tests::tree_history_independence_randomized_multilevel_edits"
    "tree_builder::tests::tree_history_independence_build_orders_and_root_growth_collapse"
    "tree_builder::tests::tree_history_independence_local_edits_share_unaffected_nodes"
    "tree_builder::tests::tree_boundaries_cursor_seeks_and_crosses_nodes"
    "tree_builder::tests::tree_history_independence_properties_survive_edits"
    "tree_builder::tests::tree_boundaries_exact_cap_resets_compression_and_rejects_oversize"
    "tree_builder::tests::tree_history_independence_point_edits_preserve_path_invariants"
    "tree_builder::tests::tree_history_independence_hardlinks_are_incremental_and_exact"
    "tree_builder::tests::tree_history_independence_conflict_summary_and_context_widening"
    "tree_builder::tests::tree_history_independence_multilevel_root_collapse"
    "tree_builder::tests::tree_history_independence_noop_preserves_root_and_emits_nothing"
    "tree_builder::tests::tree_history_independence_conditional_directory_ancestors"
    "tree_builder::tests::tree_history_independence_hardlink_members_follow_persistent_edits"
    "tree_builder::tests::tree_history_independence_hardlink_members_follow_atomic_relabeling"
  ];

  nativeStdTests = [
    "guard::snapshot::tests::qualified_occurrences_preserve_shared_layer_contexts"
    "guard::snapshot::tests::retained_graft_addresses_bind_canonical_root_usage_and_geometry"
    "guard::snapshot::grafts::tests::longest_shared_path_is_independent_of_graft_visitation_order"
    "guard::snapshot::grafts::tests::physical_graft_depth_limit_accepts_boundary_and_withholds_invalid_certificates"
    "guard::snapshot::grafts::tests::conflict_candidates_and_present_base_preserve_distinct_graft_slots"
    "guard::snapshot::grafts::tests::retained_graft_validation_requires_exact_root_usage_and_minimum"
    "indexing::tests::load_source_reads_unbound_namespace_without_auxiliary_reads"
    "indexing::tests::load_source_preserves_shared_grafts_and_internal_physical_contexts"
    "indexing::tests::load_source_keeps_typed_source_failures_and_selected_revisions"
    "indexing::tests::load_source_drives_initialization_and_loss_rebuild_without_index_evidence"
    "indexing::tests::index_loader_loads_bound_hierarchical_graph_without_mutation"
    "indexing::tests::index_loader_preserves_physical_and_contextual_node_checks"
    "indexing::tests::index_loader_reports_missing_bindings_and_unavailable_evidence"
    "indexing::tests::index_loader_refuses_divergent_relationships_and_keeps_work_separate"
    "indexing::tests::layer::load_layer_source_preserves_explicit_usage_and_canonical_closure"
    "indexing::tests::layer::load_layer_index_checks_complete_owner_binding_without_ordinary_fallback"
  ];

  nativeTokioTests = [
    "bucket::content::meta_batch::verification_tests::metadata_confirmation_reuses_only_identical_pack_parsing"
    "bucket::content::meta_batch::verification_tests::metadata_confirmation_rechecks_each_member_and_physical_read"
    "bucket::content::meta_batch::verification_tests::metadata_confirmation_reuse_never_crosses_batches_or_catalog_geometry"
    "guard::history::completion::owner_preparation_tests::repeated_owner_preparation_reuses_only_fixed_canonical_tree_work"
    "guard::history::completion::owner_preparation_tests::owner_preparation_reuse_preserves_each_occurrence_policy_and_role"
    "guard::history::completion::owner_preparation_tests::owner_preparation_reuse_never_crosses_inputs_geometry_or_invocations"
    "guard::history::candidate_preparation_tests::identical_candidate_preparation_reuses_only_operation_local_pure_work"
    "guard::history::candidate_preparation_tests::candidate_preparation_reuse_distinguishes_complete_inputs_and_typed_geometry"
    "guard::history::candidate_preparation_tests::candidate_preparation_reuse_rechecks_physical_and_issuer_refusals"
    "guard::history::completion::active::relationship_reuse_tests::repeated_grafts_reuse_one_complete_present_relationship"
    "guard::history::completion::active::relationship_reuse_tests::completed_relationship_reuse_stays_with_one_call_and_store"
    "guard::history::completion::active::relationship_reuse_tests::completed_relationship_reuse_distinguishes_explicit_tree_usage"
    "guard::history::completion::active::relationship_reuse_tests::completed_relationship_reuse_distinguishes_attribute_and_full_preparation"
    "guard::history::completion::active::relationship_reuse_tests::missing_bindings_are_rechecked_without_completed_relationship_reuse"
    "guard::history::completion::active::relationship_reuse_tests::completed_relationship_reuse_cannot_cross_revisions_or_minimum"
    "guard::history::completion::active::relationship_reuse_tests::relationship_reuse_preserves_original_store_refusals_and_new_owner_divergence"
    "guard::history::completion::active::relationship_reuse_tests::repeated_occurrence_policy_and_structural_role_refusals_precede_reuse"
    "guard::authoring::tests::authoring_attribute_two_is_selected_before_candidate_signing"
    "guard::authoring::tests::selected_required_index_publishes_real_context_and_full_carriers"
    "guard::authoring::tests::selected_required_index_refuses_divergence_before_immutable_effects"
    "guard::authoring::tests::selected_required_index_preserves_old_inert_historical_profiles"
    "guard::authoring::tests::selected_required_index_distinguishes_preserved_gaps_and_dropped_bindings"
    "guard::authoring::tests::selected_required_index_policy_and_rollback_retain_actual_view_selection"
    "guard::authoring::tests::selected_required_index_adapter_and_reopen_keep_installed_inputs"
    "guard::authoring::tests::selected_required_index_refuses_existing_guard_profile_replacement"
    "guard::read::indexes::tests::native_index_lookup_matches_sha256_and_deduplicates_authorized_occurrences"
    "guard::read::indexes::tests::native_index_lookup_filters_current_acl_trust_and_producer_context"
    "guard::read::indexes::tests::native_index_lookup_reports_gaps_even_when_candidate_range_is_empty"
    "guard::read::indexes::tests::native_index_lookup_selects_fallback_only_without_owner_binding"
    "guard::read::indexes::tests::native_index_lookup_rechecks_held_current_controls_before_return"
    "guard::read::indexes::tests::native_index_lookup_separates_loading_validation_candidates_occurrences_and_current_work"
    "guard::index_backfill::tests::native_index_backfill_reuses_checked_side_value_without_plaintext_reads"
    "guard::index_backfill::tests::native_index_backfill_reports_unavailable_or_invalid_evidence_as_gaps"
    "guard::index_backfill::tests::native_index_backfill_rechecks_producer_current_and_final_publication"
    "guard::index_backfill::tests::native_index_backfill_closes_required_inline_and_index_gaps_in_real_commit"
    "guard::index_backfill::tests::native_index_backfill_preserves_complete_carriers_after_protected_reopen"
    "guard::index_backfill::tests::native_index_backfill_updates_existing_required_binding_in_real_commit"
    "guard::index_maintenance::tests::native_index_verify_reports_divergence_without_mutation"
    "guard::index_maintenance::tests::native_index_rebuild_recovers_divergent_and_missing_auxiliary_closures"
    "guard::index_maintenance::tests::native_index_rebuild_rechecks_original_current_producer_and_final_ack"
    "guard::history::completion::indexes::tests::historical_index_completion_validates_real_signed_owner_and_full_carriers"
    "guard::history::completion::indexes::tests::historical_index_completion_preserves_repeated_occurrence_policy_contexts"
    "guard::history::completion::indexes::tests::historical_index_completion_refuses_divergent_or_incomplete_relationships"
    "guard::history::completion::indexes::tests::historical_index_completion_keeps_missing_binding_and_conflict_incomplete"
    "guard::history::completion::indexes::tests::historical_index_completion_uses_independently_installed_attribute_profile"
    "guard::history::completion::indexes::tests::historical_index_completion_rechecks_full_profile_only_after_history_finish"
    "guard::history::completion::indexes::tests::historical_index_completion_loads_exact_staged_and_stored_nodes_read_only"
    "guard::history::completion::indexes::tests::historical_index_completion_validates_structural_placement_without_requirements"
    "guard::authoring::tests::publication::locality::native_index_propagation_selects_only_affected_immutable_graft_entries"
    "guard::authoring::tests::publication::locality::native_index_propagation_preserves_repeated_grafts_and_conflict_refusal"
    "guard::authoring::tests::publication::locality::native_index_propagation_keeps_preparation_outside_delta_and_boundary_work"
    "guard::admission::index_writer::propagation::tests::prepared_graft_targets_batch_conflict_candidates_and_present_base"
    "guard::admission::index_writer::propagation::tests::prepared_graft_targets_keep_repeated_occurrences_and_skip_equal_targets"
    "guard::admission::index_writer::propagation::tests::prepared_graft_targets_refuse_inconsistent_owned_lookup_inputs"
    "ref_advance::active_completion_tests::native_active_completion_dropped_required_owner_binding_refuses_publication"
    "ref_advance::active_completion_tests::native_active_completion_verifies_indexed_owner_before_selected_ack"
    "ref_advance::active_completion_tests::native_active_completion_checks_every_shared_graft_occurrence"
    "ref_advance::active_completion_tests::native_active_completion_missing_primary_never_selects_ref_or_lineage"
    "ref_advance::active_completion_tests::native_active_completion_legacy_one_never_coerces_indexed_view"
    "ref_advance::active_completion_tests::native_active_completion_conflicting_same_view_selection_refuses"
    "ref_advance::active_completion_tests::native_active_completion_checks_each_signed_requirement_field"
    "ref_advance::active_completion_tests::native_active_completion_late_original_failure_promotes_no_views"
    "ref_advance::active_completion_tests::native_active_metadata_admits_index_roles_but_not_namespace_use"
    "ref_advance::active_completion_tests::native_active_completion_divergent_primary_never_promotes"
    "ref_advance::disclosure_tests::disclosure_projection_safe_index_rebuild_requires_current_attribute_producers"
    "guard::index_contract_tests::native_index_key_limit_refuses_before_publication_effects"
    "guard::index_contract_tests::multi_edit::source::events::tests::repeated_targets_with_distinct_hops_match_independently_of_order"
    "guard::index_contract_tests::multi_edit::source::events::tests::swapping_ordinary_costs_between_occurrences_is_rejected"
    "guard::index_contract_tests::multi_edit::source::events::tests::duplicate_occurrence_cannot_replace_an_equal_cost_sibling"
    "guard::index_contract_tests::multi_edit::source::events::tests::distinct_previous_root_contexts_are_not_conflated"
    "guard::index_contract_tests::multi_edit::source::events::tests::boundary_owned_node_opens_are_checked_for_the_exact_occurrence"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically_1024_adversarial"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically_2048_ordinary"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically_2048_adversarial"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically_4096_ordinary"
    "guard::index_contract_tests::native_index_multi_edit_batches_and_resynchronizes_canonically_4096_adversarial"
  ];

  # Registered growing-population witnesses must qualify before this blocker
  # can be removed; an inventory entry alone does not establish DRV-29.
  qualificationBlockers = [
    "DRV-29: native growing-population batched edits and independently bounded canonical resynchronization"
  ];

  groups = [
    {
      name = "core";
      package = "terrane-core";
      features = "";
      selectors = coreTests;
    }
    {
      name = "native-std";
      package = "terrane";
      features = "--no-default-features --features std";
      selectors = nativeStdTests;
    }
    {
      name = "native-tokio";
      package = "terrane";
      features = "--no-default-features --features tokio,surface-sdk";
      selectors = nativeTokioTests;
    }
  ];

  runGroup = group: let
    directory = "$out/logs/${group.name}";
    required = lib.escapeShellArg (builtins.toJSON group.selectors);
    runCase = selector: let
      name = lib.escapeShellArg selector;
      report = "${directory}/${selector}.log";
      expected = lib.escapeShellArg (builtins.toJSON [selector]);
    in ''
      if ! cargo test --frozen --offline -p ${group.package} ${group.features} \
        --lib ${name} -- --exact --test-threads=1 > "${report}" 2>&1; then
        cat "${report}" >&2
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution "${report}" ${expected}
    '';
  in ''
    mkdir -p "${directory}"
    if ! cargo test --frozen --offline -p ${group.package} ${group.features} \
      --lib -- --list > "${directory}/inventory.log" 2>&1; then
      cat "${directory}/inventory.log" >&2
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py inventory \
      "${directory}/inventory.log" ${required}
    ${builtins.concatStringsSep "\n" (map runCase group.selectors)}
  '';
in {
  index-tree-maintenance = sourceGate "index-tree-maintenance" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runGroup groups)}

    # Existing prerequisites must execute, but cannot certify missing witnesses.
    ${lib.optionalString (qualificationBlockers != []) ''
      printf '%s\n' ${builtins.concatStringsSep " " (map lib.escapeShellArg qualificationBlockers)} >&2
      exit 1
    ''}
    printf 'PASS: exact core, native std and checked native index contracts\n' > "$out/result"
  '';
}

{sourceGate, ...}: let
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output or "test " + sys.argv[2] + " ... ok" not in output)' "$TMPDIR/test.log" "${name}"
  '';
in {
  # Cold native forks need actual selected lineage and zero TreeNode I/O.
  # Keep algebra-fork registered as pending until that qualification exists.
  algebra-graft = sourceGate "algebra-graft" ''
    cd crates
    ${runTest "algebra::tests::graft_reuses_target_and_nested_lookup_resolves"}
    ${runTest "algebra::tests::graft_requires_explicit_inline_replacement"}
    ${runTest "algebra::tests::split_inline_matches_direct_construction"}
    ${runTest "algebra::tests::split_graft_shares_the_target_without_walking_its_nodes"}
    ${runTest "algebra::tests::split_relabels_hardlinks_within_and_across_prefix"}
    ${runTest "algebra::tests::flatten_checks_authority_and_preserves_lookup"}
    ${runTest "algebra::tests::flatten_prefixes_hardlink_identity"}
    ${runTest "algebra::tests::flatten_rejects_changed_effective_trust"}
    ${runTest "algebra::tests::graft_relabels_surviving_hardlink_identity_atomically"}
    ${runTest "algebra::tests::overlay_precedence_whiteouts_and_materialization_agree"}
    ${runTest "algebra::tests::overlay_ranges_match_independent_point_updates_and_canonical_roots"}
    ${runTest "algebra::tests::graft_recipe_retains_metadata_and_binds_materialized_commit"}
    ${runTest "algebra::tests::graft_certificates_skip_large_unchanged_parent_nodes"}
    ${runTest "algebra::tests::graft_certificates_replace_deep_targets_using_exact_height"}
    ${runTest "algebra::tests::graft_and_split_seek_separator_range_past_punctuation_siblings"}
    ${runTest "algebra::tests::graft_lookup_accepts_64_edges_and_rejects_65"}
    ${runTest "algebra::domain::tests::graft_preserves_exact_previous_private_ownership"}
    ${runTest "algebra::domain::tests::split_preserves_inherited_private_and_tenant_ownership"}
    ${runTest "algebra::domain::tests::overlay_recipes_bind_effective_domain_and_require_verification"}
    ${runTest "algebra::domain::tests::merge_preserves_effective_ownership_at_each_changed_graft_root"}
    ${runTest "algebra::domain::tests::flatten_preserves_resolved_parent_private_owner"}
    ${runTest "algebra::domain::tests::merge_fast_forward_preserves_unchanged_root_without_domain_reencoding"}
    ${runTest "algebra::domain::tests::conflicting_effective_bindings_are_rejected"}
    ${runTest "algebra::domain::tests::graft_retains_graft_override_owner_instead_of_raw_root_domain"}
    ${runTest "algebra::domain::tests::fold_filters_preserve_the_source_owner_before_merging"}
    printf 'PASS: pure graft, split, flatten, overlay and resolved ownership\n' > "$out/result"
  '';

  algebra-diff = sourceGate "algebra-diff" ''
    cd crates
    ${runTest "algebra::tests::diff_is_ordered_and_skips_equal_root"}
    ${runTest "algebra::tests::diff_local_change_skips_shared_nodes"}
    ${runTest "algebra::tests::diff_descent_reports_nested_implied_root_properties"}
    ${runTest "algebra::tests::diff_descent_accepts_64_edges_and_rejects_65"}
    ${runTest "algebra::tests::diff_and_graft_lookup_reject_resolver_identity_mismatch"}
    printf 'PASS: pure ordered Merkle comparison and subtree skipping\n' > "$out/result"
  '';

  algebra-merge = sourceGate "algebra-merge" ''
    cd crates
    ${runTest "algebra::tests::merge_rules_and_fast_forward"}
    ${runTest "algebra::tests::merge_conflicts_and_ordered_policies"}
    ${runTest "algebra::tests::deletion_conflict_is_representable_without_nested_conflicts"}
    ${runTest "algebra::tests::fork_and_fold_preserve_parents_and_report_exclusions"}
    ${runTest "algebra::tests::merge_randomized_reference_model_and_symmetric_policy"}
    ${runTest "algebra::tests::merge_changed_grafts_returns_materialized_targets"}
    ${runTest "algebra::tests::merge_commit_binding_records_order_recipe_and_conflict_profile"}
    ${runTest "algebra::tests::fork_and_fold_binding_inherits_origins_without_reintroduction"}
    ${runTest "algebra::tests::trusted_recipe_binds_verifier_configuration_and_receipts"}
    ${runTest "algebra::tests::root_properties_diff_and_three_way_merge_are_explicit"}
    ${runTest "algebra::tests::directory_conflicts_retain_children_until_nondirectory_resolution"}
    ${runTest "algebra::tests::surface_inputs_can_produce_an_ordinary_conflicted_tree"}
    ${runTest "algebra::tests::trusted_context_rejects_bad_syntax_and_handles_deep_configuration"}
    ${runTest "algebra::tests::trusted_context_decoding_checks_registered_attribute_names"}
    ${runTest "algebra::tests::trusted_context_decoding_checks_encoded_byte_map_order"}
    ${runTest "algebra::tests::trusted_context_decoding_cannot_authorize_merge"}
    ${runTest "algebra::tests::trusted_merge_binds_signed_sides_and_reverifies_recipe"}
    ${runTest "algebra::tests::trusted_fold_replays_exclusions_before_rebinding_signed_input"}
    ${runTest "algebra::tests::merge_prefer_newer_binds_verified_timestamps_and_falls_back_on_ties"}
    ${runTest "algebra::tests::merge_adopts_unchanged_base_ranges_from_incoming_subtrees"}
    ${runTest "algebra::tests::merge_certificates_track_nested_conflicts_without_rescanning_fast_forward"}
    ${runTest "algebra::tests::merge_updates_complete_hardlink_sets_atomically"}
    ${runTest "algebra::tests::merge_recurses_through_64_graft_edges"}
    ${runTest "algebra::merge::tests::trusted_nested_graft_pruning_retains_full_path_on_splice_fallback"}
    ${runTest "algebra::recipe::tests::recipe_decode_roundtrips_and_rejects_noncanonical_inputs"}
    ${runTest "algebra::recipe::tests::overlay_recipe_preserves_precedence"}
    ${runTest "algebra::recipe::tests::merge_recipe_preserves_policy_order"}
    printf 'PASS: pure merge, fold bindings, conflict policies and verified recipes\n' > "$out/result"
  '';

  tree-acyclic = sourceGate "tree-acyclic" ''
    cd crates
    ${runTest "algebra::tests::acyclic_validation_rejects_missing_targets"}
    ${runTest "algebra::tests::acyclic_checked_graft_and_reader_reject_alias_cycles"}
    ${runTest "algebra::tests::acyclic_boundary_accepts_64_edges_with_cached_frontiers"}
    ${runTest "algebra::tests::graft_lookup_accepts_64_edges_and_rejects_65"}
    ${runTest "algebra::tests::diff_descent_accepts_64_edges_and_rejects_65"}
    ${runTest "algebra::tests::merge_recurses_through_64_graft_edges"}
    ${runTest "tree_format::tests::graft_chain_rejects_cycles_and_excessive_depth"}
    printf 'PASS: pure graft DAG checks and exact depth limits\n' > "$out/result"
  '';
}

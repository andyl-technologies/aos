{sourceGate, ...}: let
  runCase = path: ''
    cargo test --frozen --offline -p terrane-core --lib ${path} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output or "test " + sys.argv[2] + " ... ok" not in output)' "$TMPDIR/test.log" "${path}"
  '';
  runTest = name: runCase "provenance::tests::${name}";
in {
  prov-commit-signature = sourceGate "prov-commit-signature" ''
    cd crates
    cargo build --frozen --offline --no-default-features -p terrane-core --lib
    ${runTest "prov_commit_signature_binds_exact_preimage_and_signed_identity"}
    ${runTest "prov_commit_verify_rejects_tampering_missing_token_and_wrong_context"}
    ${runTest "prov_commit_signature_uses_last_attenuation_key"}
    ${runTest "context::prov_commit_signature_binds_context_even_when_changed_scope_is_authorized"}
    ${runTest "context::prov_commit_history_preserves_original_scope_with_narrow_root_grants"}
    ${runTest "context::prov_commit_context_rejects_tampered_scope_and_unvalidated_roots"}
    ${runTest "context::prov_commit_authored_requires_context_and_legacy_bytes_remain_explicit"}
    ${runTest "context::prov_commit_context_canonicalizes_unsigned_root_pairs_and_rejects_duplicates"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_copied_fork_widening_requires_original_destination_admin"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_copied_fork_retaining_or_narrowing_needs_only_original_commit"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_copied_fork_rejects_missing_or_mismatched_original_baseline"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_later_admin_does_not_repair_original_copied_fork_authority"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_same_ref_different_original_owner_requires_independent_comparison"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_explicit_same_ref_continuity_requires_parent_original_evidence"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_copied_fork_comparison_uses_only_view_root_policy_witness"}
    ${runTest "root_context::bootstrap_fork::prov_commit_bootstrap_legacy_parent_requires_independent_original_candidate_baseline"}
    ${runTest "root_context::recorded::recorded_scope_verification_preserves_fixed_interpretations_and_original_authority"}
    ${runTest "root_context::recorded::private_cases::recorded_scope_reverification_and_history_union_refuse_interpretation_conflicts"}
    ${runTest "snapshot::prov_snapshot_signature_binds_exact_preimage_and_terminal_key"}
    ${runTest "snapshot::prov_snapshot_verification_rejects_wrong_target_scope_and_signature"}
    ${runTest "snapshot::prov_snapshot_tag_scope_accepts_admin_implication_and_rejects_commit_only"}
    ${runTest "snapshot::prov_snapshot_tag_scope_enforces_exact_source_caveats"}
    printf 'PASS: pure terminal-key commit signatures and embedded authorization\n' > "$out/result"
  '';

  prov-selector-presets = sourceGate "prov-selector-presets" ''
    cd crates
    ${runTest "prov_selector_presets_parse_closed_ast_and_deep_input"}
    ${runTest "prov_selector_presets_distinguish_fold_acceptance_from_introduction"}
    ${runTest "prov_entry_preserve_metadata_and_sources_without_parent_ancestry"}
    ${runTest "prov_selector_presets_missing_evidence_stays_absent_under_negation"}
    ${runTest "selector::prov_selector_presets_missing_acceptance_ancestry_stays_absent_under_negation"}
    ${runTest "selector::prov_selector_presets_inherited_root_acceptance_remains_required_for_any_view"}
    ${runTest "selector::prov_selector_presets_attribute_names_follow_registered_vocabulary"}
    ${runTest "prov_entry_preserve_rejects_unverified_tree_and_invalid_ancestors"}
    ${runTest "prov_fold_reintroduction_records_verified_original_introduction"}
    ${runTest "prov_selector_presets_root_policy_cannot_be_widened_by_view"}
    ${runTest "prov_attribute_producer_is_independent_of_content_introduction"}
    ${runTest "prov_selector_presets_graft_policy_applies_without_subroot_bypass"}
    ${runTest "prov_fold_acceptance_survives_receipt_path_changes"}
    ${runTest "prov_selector_presets_descendant_baseline_cannot_widen_ancestor_trust"}
    ${runTest "prov_selector_presets_signed_key_names_terminal_public_key_bytes"}
    ${runTest "prov_entry_preserve_index_receipts_use_checked_opaque_keys"}
    ${runTest "prov_selector_presets_candidate_decisions_bind_full_signed_entry"}
    ${runTest "prov_attribute_acceptance_does_not_borrow_content_acceptance"}
    ${runTest "prov_property_wrappers_resolve_inheritance_and_graft_overrides"}
    ${runTest "prov_external_sources_preserve_producers_without_granting_acceptance"}
    ${runTest "prov_attribute_producer_rejects_equal_value_inherited_on_changed_content"}
    ${runTest "history_merge::prov_history_union_preserves_completed_scopes_and_is_idempotent"}
    ${runTest "history_merge::prov_history_union_rejects_unfinished_contexts_on_either_side"}
    ${runTest "history_merge::prov_history_union_rejects_provisional_contexts_on_either_side"}
    ${runTest "history_merge::prov_history_union_rejects_different_original_verification_contexts"}
    ${runTest "history_merge::prov_history_union_rejects_different_profile_limits"}
    ${runTest "history_merge::prov_history_union_rejects_conflicting_tree_interpretations"}
    ${runTest "history_merge::prov_history_union_rejects_conflicting_retained_bootstrap_associations"}
    ${runTest "disclosure::boundaries::prov_history_union_preserves_completed_disclosure_boundaries"}
    ${runTest "disclosure::boundaries::prov_disclosure_history_import_rejects_unfinished_or_provisional_dependencies"}
    ${runTest "side_attributes::prov_history_union_preserves_selected_side_record_contexts"}
    ${runTest "side_attributes::prov_history_union_rejects_conflicting_selected_side_records_atomically"}
    ${runTest "side_attributes::prov_side_context_encoder_preserves_verified_legacy_carrying_witness"}
    ${runCase "provenance::trust::context::tests::prov_context_selected_rows_bind_view_domain_and_name"}
    ${runCase "provenance::trust::context::tests::prov_context_selected_evidence_enforces_path_and_digest_limits"}
    ${runCase "provenance::trust::context::tests::prov_context_selected_values_and_order_require_canonical_encoding"}
    ${runCase "provenance::trust::context::tests::prov_context_rejects_truncated_and_excessive_claims"}
    ${runCase "provenance::trust::encoding::recorded_tests::prov_recorded_context_encoder_preserves_explicit_fields_and_legacy_bytes"}
    ${runCase "provenance::trust::context::recorded_tests::prov_recorded_context_decoder_requires_exact_revision_and_canonical_fence"}
    ${runCase "provenance::trust::context::recorded_tests::prov_recorded_context_selected_rows_keep_existing_relationships"}
    ${runCase "provenance::trust::recorded_evaluation_tests::recorded_evaluator_binds_verified_view_and_complete_configuration"}
    ${runCase "provenance::trust::recorded_evaluation_tests::recorded_evaluator_keeps_one_interpretation_across_graft_prefixes"}
    ${runCase "provenance::trust::recorded_evaluation_tests::recorded_evaluator_refuses_missing_or_inconsistent_association"}
    ${runTest "root_context::recorded::private_cases::recorded_scope_evaluators_require_matching_retained_interpretations"}
    ${runTest "disclosure::recorded::recorded_disclosure_preserves_selected_view_interpretations_and_actual_occurrences"}
    ${runTest "disclosure::recorded::recorded_disclosure_refuses_missing_associations_and_conflicting_dependency_scopes"}
    ${runTest "disclosure::recorded::recorded_disclosure_keeps_certificate_binding_public_retention_and_attribute_producer_checks"}
    printf 'PASS: closed trust presets and verified entry preservation\n' > "$out/result"
  '';
}

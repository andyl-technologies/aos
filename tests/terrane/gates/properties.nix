{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';

  runNativeTest = name: ''
    cargo test --frozen --offline -p terrane --no-default-features --features tokio,surface-sdk --lib ${name} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output or "test " + sys.argv[2] + " ... ok" not in output)' "$TMPDIR/test.log" "${name}"
  '';
in {
  property-resolution = sourceGate "property-resolution" ''
    cd crates
    ${runTests "properties::tests::resolution"}
    ${runTests "properties::depth_tests"}
    ${runTests "gc::publication::evidence::cbor::tests::guard::property_revisions_preserve_legacy_and_bind_index_roots_exactly -- --exact"}
    ${runTests "gc::publication::evidence::cbor::tests::guard::property_revision_vocabulary_mismatches_refuse -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::active_tests::active_registry_supports_exact_three_two_one_without_relabeling_legacy -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::tests::later_property_names_remain_inert_under_their_recorded_revision -- --exact"}
    ${runTests "gc::publication::evidence::cbor::tests::lineage::enclosing_lineage_preserves_recorded_inert_property_names -- --exact"}
    ${runTests "indexing::tests::owner_bindings_require_canonical_noninherited_root_values -- --exact"}
    ${runTests "indexing::carrier_tests::gap_bindings_require_primary_root_placement_and_exact_wrapper -- --exact"}
    ${runTests "indexing::carrier_tests::structural_index_names_do_not_become_value_inputs -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::private_registry_tests::property_and_attribute_revisions_bind_structural_index_names_exactly -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::private_registry_tests::legacy_semantic_contexts_preserve_inert_index_carriers -- --exact"}
    ${runTests "properties::semantics::tests::resolution_recorded_revisions_preserve_inert_later_names -- --exact"}
    ${runTests "properties::semantics::tests::resolution_revisions_bind_defaults_and_graft_placement_exactly -- --exact"}
    ${runTests "properties::semantics::tests::resolution_unknown_revisions_and_unregistered_extensions_refuse -- --exact"}
    ${runNativeTest "ref_advance::active_completion_tests::recorded_selection_tests::table::native_recorded_selection_owned_table_distinguishes_signed_views_sharing_one_root"}
    ${runNativeTest "ref_advance::active_completion_tests::recorded_selection_tests::table::native_recorded_selection_each_conflicting_input_refuses_without_replacing_original_table"}
    ${runNativeTest "ref_advance::active_completion_tests::recorded_selection_tests::native_recorded_selection_missing_or_changed_used_association_promotes_nothing"}
    ${runNativeTest "ref_advance::active_completion_tests::recorded_selection_tests::table::native_recorded_selection_missing_head_cannot_be_recovered_from_actual_context_bearing_ack"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_preserve_defaults_and_inert_names -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_follow_full_and_parent_graft_paths -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_reject_untrusted_names_and_placement -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::authoring_plans_use_explicit_recorded_property_context -- --exact"}
    ${runTests "provenance::tests::root_context::recorded::recorded_scope_verification_preserves_fixed_interpretations_and_original_authority -- --exact"}
    ${runNativeTest "guard::view_selection::adapter_tests::explicit_read_configuration_refuses_missing_view_root_and_mode_mismatches"}
    ${runNativeTest "guard::view_selection::adapter_tests::retained_read_configuration_preserves_fixed_graft_interpretations"}
    ${runNativeTest "ref_advance::active_completion_tests::recorded_selection_tests::evaluators::selected_read_configuration_constructs_checked_recorded_evaluators"}
    ${runNativeTest "guard::view_selection::adapter_tests::adapter_configuration_preserves_legacy_and_explicit_modes"}
    ${runNativeTest "guard::view_selection::adapter_tests::adapter_configuration_retains_per_view_fences_and_refuses_missing_pairs"}
    ${runNativeTest "guard::view_selection::adapter_tests::adapter_configuration_preserves_recorded_graft_semantics"}
    ${runNativeTest "guard::view_selection::historical_tests::historical_root_witnesses_retain_recorded_occurrence_interpretations"}
    ${runNativeTest "guard::view_selection::historical_tests::historical_root_witnesses_use_one_candidate_interpretation_for_prior_comparison"}
    ${runTests "provenance::tests::root_context::recorded::historical_execution::recorded_removed_scope_uses_candidate_interpretation_of_raw_prior_roots -- --exact"}
    ${runNativeTest "guard::view_selection::historical_tests::historical_scope_dispatch_preserves_checked_interpretations_and_refusals"}
    ${runTests "properties::tests::domain_reference_recorded_graft_admission_preserves_trusted_later_bindings -- --exact"}
    ${runTests "properties::tests::domain_reference_recorded_graft_admission_keeps_placement_and_policy_refusals -- --exact"}
    ${runNativeTest "guard::view_selection::historical_tests::historical_graft_admission_preserves_inert_overrides_through_publication_and_rollback"}
    ${runNativeTest "guard::view_selection::historical_tests::historical_graft_admission_refuses_untrusted_malformed_and_unauthorized_overrides_before_publication"}
    printf 'PASS: closed registry and view-path property resolution\n' > "$out/result"
  '';

  property-required-attrs = sourceGate "property-required-attrs" ''
    cd crates
    ${runTests "properties::tests::required_attrs"}
    printf 'PASS: changed-entry attribute requirements and completeness\n' > "$out/result"
  '';

  property-domain-reference = sourceGate "property-domain-reference" ''
    cd crates
    ${runTests "properties::tests::domain_reference"}
    printf 'PASS: disclosure references and boundary transitions\n' > "$out/result"
  '';
}

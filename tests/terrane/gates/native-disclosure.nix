{
  lib,
  sourceGate,
  ...
}: let
  qualifySuite = package: features: selector: required: ''
    cargo test --frozen --offline -p ${package} --lib ${features} ${lib.escapeShellArg selector} -- --list > "$TMPDIR/inventory.log"
    python3 ../tests/terrane/check_native_gate.py inventory "$TMPDIR/inventory.log" ${lib.escapeShellArg (builtins.toJSON required)}
    # Independent native fixtures use real operation deadlines. As in the
    # feature matrix, bound case fanout while retaining each case's own races.
    # Failed case output must survive teardown of the local test sandbox.
    if cargo test --frozen --offline -p ${package} --lib ${features} ${lib.escapeShellArg selector} -- --test-threads=1 > "$TMPDIR/native.log"; then
      python3 ../tests/terrane/check_native_gate.py execution "$TMPDIR/native.log" ${lib.escapeShellArg (builtins.toJSON required)}
    else
      native_test_status=$?
      cat "$TMPDIR/native.log" >&2
      exit "$native_test_status"
    fi
  '';

  nativeSuite = selector: names:
    qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" selector
    (map (name: "ref_advance::disclosure_tests::${name}") names);

  boundaryTests = [
    "disclosure_boundary_reopens_after_source_and_signing_seed_erasure"
    "disclosure_boundary_rejects_whole_commit_receipt_and_projection_mutations"
    "disclosure_boundary_rejects_uncovered_siblings_attributes_and_unanchored_parents"
    "disclosure_boundary_uses_public_introducer_and_public_ancestry"
    "disclosure_boundary_preserves_historical_key_windows_and_current_revocation"
    "disclosure_rotation_retains_historical_certificates_and_issues_with_new_key"
    "disclosure_rotation_denies_current_admin_and_ambiguous_issue_time_without_effects"
    "disclosure_original_binding_rejects_copied_or_conflicting_import_controls"
    "disclosure_current_authority_rechecks_both_whole_heads_tokens_epochs_and_root_acls"
    "disclosure_projection_rejects_tree_whiteout_conflict_and_index_entries"
    "disclosure_domain_reference_order_and_dedup_remain_scoped"
    "disclosure_boundary_manifest_and_multiple_source_certificates"
    "disclosure_boundary_directory_marker_and_raw_symlink_have_limited_scope"
    "disclosure_boundary_nested_and_repeated_root_occurrences_check_actual_domains"
    "disclosure_boundary_first_and_second_parent_cuts_require_complete_origins"
    "disclosure_boundary_copied_attributes_require_independent_public_producers"
    "disclosure_boundary_original_acl_verification_survives_destination_only_reopen"
    "disclosure_projection_safe_materialization_certifies_each_flattened_file"
    "disclosure_projection_safe_conflict_resolution_certifies_selected_file"
    "disclosure_projection_safe_whiteout_application_keeps_public_baseline"
    "disclosure_projection_safe_index_rebuild_requires_current_attribute_producers"
  ];

  domainCore = qualifySuite "terrane-core" "" "properties::tests::domain_reference" [
    "properties::tests::domain_reference_closed_order_and_metadata_fail_closed"
    "properties::tests::domain_reference_graft_overrides_and_dedup_scope"
    "properties::tests::domain_reference_conflict_candidates_checked_individually"
  ];

  recordedCore = qualifySuite "terrane-core" "" "provenance::tests::disclosure::recorded::" [
    "provenance::tests::disclosure::recorded::recorded_disclosure_preserves_selected_view_interpretations_and_actual_occurrences"
    "provenance::tests::disclosure::recorded::recorded_disclosure_refuses_missing_associations_and_conflicting_dependency_scopes"
    "provenance::tests::disclosure::recorded::recorded_disclosure_keeps_certificate_binding_public_retention_and_attribute_producer_checks"
  ];
in {
  # Discovery fails explicitly until the complete native boundary cases exist.
  # Successful pure codecs or empty filter selections do not qualify this gate.
  prov-disclosure-boundary = sourceGate "prov-disclosure-boundary" ''
    cd crates
    ${recordedCore}
    ${nativeSuite "ref_advance::disclosure_tests::" boundaryTests}
    printf 'PASS: protected native disclosure, public original context and complete boundary verification\n' > "$out/result"
  '';

  dom-reference-order = sourceGate "dom-reference-order" ''
    cd crates
    ${domainCore}
    ${qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" "domain::tests::dom_reference_order" [
      "domain::tests::dom_reference_order_checks_every_kind_and_incomparable_name"
      "domain::tests::dom_reference_order_rejects_empty_domain_names_before_admission"
      "domain::tests::dom_reference_order_requires_fresh_records_after_closing"
    ]}
    ${qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" "domain::native_deletion_tests::" [
      "domain::native_deletion_tests::audit_intent::domain_deletion_native_failed_audit_intent_preserves_source_and_active_route"
      "domain::native_deletion_tests::domain_deletion_native_erases_generations_and_disables_surviving_and_reopened_routes"
      "domain::native_deletion_tests::domain_deletion_native_rejects_denied_roots_and_whole_inventory_races"
      "domain::native_deletion_tests::domain_deletion_native_erases_empty_registered_namespace_and_retains_pending_on_parent_sync_failure"
    ]}
    ${nativeSuite "ref_advance::disclosure_tests::" [
      "disclosure_domain_reference_order_and_dedup_remain_scoped"
      "disclosure_current_authority_rechecks_both_whole_heads_tokens_epochs_and_root_acls"
      "disclosure_boundary_nested_and_repeated_root_occurrences_check_actual_domains"
      "disclosure_projection_rejects_tree_whiteout_conflict_and_index_entries"
    ]}
    printf 'PASS: canonical domain ordering, native deletion and independently guarded references\n' > "$out/result"
  '';

  dom-dedup-scope = sourceGate "dom-dedup-scope" ''
    cd crates
    ${domainCore}
    ${qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" "domain::native_storage_tests::" [
      "domain::native_storage_tests::dom_dedup_scope_native_chunks_manifests_and_nodes_are_independent_after_reopen"
      "domain::native_storage_tests::dom_dedup_scope_native_disclosure_verifies_recompressed_plaintext"
    ]}
    ${nativeSuite "ref_advance::disclosure_tests::" [
      "disclosure_domain_reference_order_and_dedup_remain_scoped"
      "disclosure_current_authority_rechecks_both_whole_heads_tokens_epochs_and_root_acls"
      "disclosure_boundary_manifest_and_multiple_source_certificates"
      "disclosure_boundary_reopens_after_source_and_signing_seed_erasure"
    ]}
    printf 'PASS: isolated native domain records, current disclosure authority and destination-only reopening\n' > "$out/result"
  '';

  prov-commit-verify = sourceGate "prov-commit-verify" ''
    cd crates
    ${nativeSuite "ref_advance::" boundaryTests}
    ${qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" "guard::current_history::tests::" [
      "guard::current_history::tests::native_current_history_rejects_invalid_token_before_content_reads"
      "guard::current_history::tests::native_current_history_walks_each_authorization_independently"
      "guard::current_history::tests::native_current_purpose_refuses_changed_whole_ref_epoch"
      "guard::current_history::tests::native_current_history_refuses_missing_actual_original_association"
      "guard::current_history::tests::native_current_reader_refuses_cached_data_after_real_token_expiry"
      "guard::current_history::tests::native_current_read_refuses_signed_acl_revocation"
    ]}
    ${qualifySuite "terrane" "--no-default-features --features tokio,surface-sdk" "guard::history::current_reads::tests::" [
      "guard::history::current_reads::tests::ordinary_current_binding_preserves_requested_target_and_actual_scope"
      "guard::history::current_reads::tests::current_scope_refuses_candidate_layer_and_partially_held_observations"
    ]}
    printf 'PASS: native ref admission, historical original authority and complete disclosure boundaries\n' > "$out/result"
  '';
}

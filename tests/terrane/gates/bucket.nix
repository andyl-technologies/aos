{sourceGate, ...}: let
  activeOpenTests = [
    "publication::activation::tests::active_open_runs_real_fixed_probes_and_preserves_registered_selection"
    "publication::activation::tests::active_open_refuses_noop_create_probes_despite_unchanged_present_bytes"
    "publication::activation::tests::active_open_refuses_wrong_binding_range_before_selected_timestamp_publication"
    "publication::activation::tests::active_open_refuses_cap_replacement_and_unsafe_ancestry_after_range_read"
    "publication::activation::tests::active_open_missing_coordination_or_registration_creates_nothing"
    "publication::activation::tests::active_open_unavailable_retention_refuses_before_repair_or_probe"
    "publication::activation::tests::canceled_active_open_probe_retains_real_exclusion_until_worker_completion"
    "publication::activation::tests::active_probe_stale_whole_cap_preimage_refuses_a_valid_successor_without_effects"
  ];

  heldContentTests = [
    "publication::held_read_tests::content::held_content_get_preserves_all_exact_reads_and_reduces_metadata_dispatch"
    "publication::held_read_tests::content::held_content_get_refuses_actual_ancestry_change_after_body_read"
    "publication::held_read_tests::content::held_content_get_refuses_replaced_leaf_even_when_body_bytes_match"
    "publication::held_read_tests::content::held_content_get_preserves_unavailable_read_and_complete_body_verification"
    "publication::held_read_tests::content::held_content_get_rechecks_intervening_real_publication_before_return"
    "publication::held_read_tests::content::held_content_catalog_rejects_symlinked_cache_nodes_without_reads_or_repair"
  ];

  controlFenceTests = [
    "publication::held_read_tests::control_fences::control_recheck_batches_all_three_walks_with_duplicate_entry_parity"
    "publication::held_read_tests::control_fences::control_recheck_short_combined_walk_refuses_before_leaf_reads"
    "publication::held_read_tests::control_fences::control_recheck_earlier_unsafe_walk_precedes_later_missing_coordination_parent"
    "publication::held_read_tests::control_fences::control_recheck_retains_final_leaf_check_after_combined_walk_mutation"
  ];

  protectedReadTests = [
    "publication::control::tests::activation_staging_accepts_only_its_exact_protected_key"
    "publication::control::tests::protected_native_consumer_preserves_complete_selected_record_transcript"
    "publication::control::tests::protected_native_consumer_preserves_missing_parent_and_leaf_absence"
    "publication::control::tests::protected_native_consumer_rejects_unsafe_parent_before_later_missing_parent"
    "publication::control::tests::protected_native_consumer_checks_leaf_policy_before_body_or_fallback"
    "publication::control::tests::protected_native_consumer_propagates_hook_errors_and_validates_keys_first"
    "publication::control::tests::protected_scalar_fallback_keeps_before_body_failure_and_after_body_mode_check"
    "publication::control::tests::protected_native_consumer_keeps_final_selected_resolver_physical_fence"
  ];

  indexPolicyTests = [
    "publication::held_read_tests::burns::represented_burn_without_old_artifacts_keeps_fresh_reads_and_denies_detached_alias"
    "publication::held_read_tests::burns::index_policy_keeps_unknown_burn_completeness_distinct_from_known_empty"
    "publication::held_read_tests::burns::detached_index_policy_checks_canonical_header_and_preserves_other_index_formats"
    "publication::held_read_tests::burns::index_alias_filter_preserves_missing_bodies_and_original_error_priority"
  ];

  physicalExclusionTests = [
    "retirement_tests::physical_exclusion_overrides_live_rows_during_fresh_admission"
    "retirement_tests::raw_publication_refuses_mixed_live_row_exclusion_without_changing_selected_catalog"
  ];

  nativeCreationTests = [
    "native_creation_commits_pack_and_index_from_real_container_writers"
    "native_creation_selects_pending_before_any_artifact_mutation"
    "native_creation_preserves_imported_unknown_and_existing_versions"
    "native_creation_recreation_uses_fresh_nonce_for_equal_bytes"
    "native_creation_refuses_owned_journals_and_invalid_preimages"
    "native_creation_sync_failures_never_acknowledge_unqualified_versions"
    "native_creation_cancellation_retains_actual_exclusion_through_completion"
    "native_creation_readonly_and_unavailable_retention_create_nothing"
  ];

  focusedTests = ''
    run_bucket_test() {
      test_name=$1
      cargo test --frozen --offline -p terrane --features tokio --lib -- --list > "$TMPDIR/bucket-tests.txt"
      python3 - "$TMPDIR/bucket-tests.txt" "$test_name" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    if f"{sys.argv[2]}: test" not in names:
        raise SystemExit(f"required bucket test is missing: {sys.argv[2]}")
    PYTEST
      cargo test --frozen --offline -p terrane --features tokio --lib "$test_name" -- --exact
    }

    run_core_bucket_test() {
      test_name=$1
      cargo test --frozen --offline -p terrane-core --lib -- --list > "$TMPDIR/core-bucket-tests.txt"
      python3 - "$TMPDIR/core-bucket-tests.txt" "$test_name" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    if f"{sys.argv[2]}: test" not in names:
        raise SystemExit(f"required core bucket test is missing: {sys.argv[2]}")
    PYTEST
      cargo test --frozen --offline -p terrane-core --lib "$test_name" -- --exact
    }
  '';

  gate = name: tests:
    sourceGate name ''
      cd crates
      ${focusedTests}
      ${builtins.concatStringsSep "\n" (map (test: "run_bucket_test bucket::${test}") tests)}
      printf 'PASS: ${name} native file bucket conformance\n' > "$out/result"
    '';
in {
  store-idempotent-put = gate "store-idempotent-put" (physicalExclusionTests ++ ["content_tests::repeated_put_preserves_first_encoding_and_survives_reopen" "readmission_tests::verified_reupload_replaces_gc_retired_placement_without_restoring_old_pack"]);
  store-verify-on-put = gate "store-verify-on-put" ["content_tests::admission_validates_identity_length_profile_and_independent_dedup_context"];
  store-verify-on-get = gate "store-verify-on-get" (heldContentTests ++ indexPolicyTests ++ ["fault_tests::dictionary_backend_unavailability_preserves_put_and_get_failure_kinds" "content_tests::corrupt_bytes_outside_requested_range_are_never_returned"]);
  store-ranged-get = gate "store-ranged-get" ["content_tests::ranges_address_verified_encoded_bytes_and_check_overflow" "publication::held_read_tests::content::held_content_get_preserves_all_exact_reads_and_reduces_metadata_dispatch" "publication::held_read_tests::content::held_content_get_preserves_unavailable_read_and_complete_body_verification"];
  store-has-batched = gate "store-has-batched" ["content_tests::batched_membership_preserves_order_duplicates_and_virtual_empty_chunk"];
  store-ref-cas = gate "store-ref-cas" ["tests::whole_record_cas_has_one_winner_across_independent_opens" "tests::ref_successors_fence_epoch_home_and_sequence" "selection_tests::candidates_bind_the_complete_proposal_and_predecessor_before_head_cas" "selection_tests::independent_candidates_select_one_history_under_concurrent_cas"];
  store-ref-log-append-once = gate "store-ref-log-append-once" ["version_tests::v2_numbered_logs_require_migration_and_preserve_exact_existing_bytes" "tests::tags_and_reflogs_never_replace_existing_bytes" "tests::missing_reflog_with_committed_horizon_is_corruption" "tests::committed_reflog_must_match_the_complete_ref_record" "tests::live_watch_waits_for_authoritative_ref_publication_and_replays_sequences" "selection_tests::abandoned_candidates_leave_the_same_sequence_available_to_a_new_writer" "selection_tests::selected_candidates_coexist_with_legacy_numbered_files"];
  store-capability-probe = sourceGate "store-capability-probe" ''
    cd crates
    ${focusedTests}
    run_bucket_test store::bindings::tests::native_lock_rejects_symlinks_hardlinks_and_replaced_open_inodes
    run_bucket_test store::bindings::tests::native_metadata_preserves_links_permissions_and_nofollow_attributes
    run_bucket_test store::protected_read::tests::protected_recipe_preserves_every_ordered_duplicate_parent
    run_bucket_test store::protected_read::tests::native_protected_read_returns_exact_body_and_same_leaf_identity
    run_bucket_test store::protected_read::tests::native_protected_read_preserves_missing_parent_and_leaf_absence
    run_bucket_test store::protected_read::tests::native_protected_read_unsafe_parent_precedes_later_missing_parent
    run_bucket_test store::protected_read::tests::native_protected_read_refuses_unsafe_leaf_without_returning_body
    run_bucket_test store::protected_read::tests::native_protected_read_refuses_hardlinked_and_symlinked_leaves
    run_bucket_test store::native_effect::tests::range::captured_range_reads_exact_bytes_at_nonzero_offset
    run_bucket_test store::native_effect::tests::range::captured_range_refuses_bytes_outside_complete_preimage
    run_bucket_test store::native_effect::tests::range::captured_range_refuses_missing_complete_preimage
    run_bucket_test store::native_effect::directory_retention::tests::wrapped_primitives_preserve_actual_fault_identity_and_bytes
    run_bucket_test store::native_effect::directory_retention::tests::nested_retention_refuses_before_actual_write
    run_bucket_test store::native_effect::directory_retention::tests::actual_directory_policy_and_parent_replacements_refuse_write
    run_bucket_test store::native_effect::directory_retention::tests::aborted_waiter_retains_directory_and_kernel_exclusion_through_durability
    run_bucket_test store::native_effect::directory_retention::tests::queued_aborted_waiter_retains_actual_directories_and_namespace_lock
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::fresh_native_creator_stages_pending_before_selected_activation
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::fresh_creation_race_returns_existing_without_repairing_winner
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::fresh_probe_preparation_checks_whole_cap_before_any_staging
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::unavailable_native_initialization_hook_refuses_before_any_effect
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::fresh_activation_requires_real_create_new_and_binding_range_probes
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::interrupted_creator_before_pending_does_not_authorize_existing_root
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::canceled_running_creator_retains_actual_directories_and_exclusion_through_staging
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::fresh_creator_enforces_actual_descriptor_modes_under_restrictive_umask
    run_bucket_test store::native_effect::publication::initialization_inputs::fresh::tests::native_creator_requires_actual_effective_uid_before_creating_any_name
    run_bucket_test store::native_effect::publication::initialization_inputs::pending::tests::pending_restart_reuses_exact_staged_transaction_and_operation_nonce
    run_bucket_test store::native_effect::publication::initialization_inputs::pending::tests::pending_restart_recovers_before_and_after_actual_genesis_slot
    run_bucket_test store::native_effect::publication::initialization_inputs::pending::tests::fresh_handoff_refuses_same_bytes_replacement_of_original_staged_leaf
    run_bucket_test store::native_effect::publication::initialization_inputs::pending::tests::canceled_running_genesis_slot_retains_actual_receipts_until_worker_acknowledgment
    run_bucket_test store::native_effect::publication::initialization_inputs::pending::tests::canceled_queued_genesis_effect_retains_actual_receipts_without_rebinding
    # A permissive inherited umask must not expose a new coordination inode.
    (umask 000; run_bucket_test store::bindings::tests::native_existing_lock_never_creates_missing_coordination)
    run_core_bucket_test bucket::records::tests::capability_publication_marker_preserves_legacy_bytes_and_rejects_unknown_versions
    run_bucket_test bucket::tests::registered_publication_marker_cannot_authorize_legacy_probe_writes
    ${builtins.concatStringsSep "\n" (map (test: "run_bucket_test bucket::${test}") ["version_tests::v1_readonly_refuses_an_empty_backend_response_after_initial_validation" "version_tests::v1_readonly_preserves_unknown_inventory_and_refuses_every_effect" "version_tests::v1_readonly_rejects_layout_transition_without_upgrading_or_writing" "tests::probe_revalidates_persisted_layout_and_profile_each_open" "tests::missing_capabilities_cache_recovers_existing_selected_state"])}
    printf 'PASS: native probe, retained initialization/recovery and canonical publication marker conformance (38 exact cases)\n' > "$out/result"
  '';
  store-list-not-authoritative = gate "store-list-not-authoritative" ["fault_tests::stale_directory_listing_cannot_change_content_or_ref_results"];
  store-validates-uploads = gate "store-validates-uploads" ["fault_tests::dictionary_backend_unavailability_preserves_put_and_get_failure_kinds" "requirement_tests::opaque_metadata_callback_verifies_real_chunks_before_every_dedup" "content_tests::configured_schema_validator_rejects_canonical_but_invalid_meta" "content_tests::admission_validates_identity_length_profile_and_independent_dedup_context" "content_tests::dictionaries_are_fetched_by_verified_chunk_identity_before_decode" "container_tests::whole_pack_import_verifies_members_without_admitting_them" "manifest_tests::manifest_admission_rechecks_nonfinal_context_after_inventory_only_import" "manifest_tests::manifest_references_accept_an_honest_nonfinal_boundary_and_verified_lengths"];
  bucket-key-registry = sourceGate "bucket-key-registry" ''
    cd crates
    ${focusedTests}
    run_bucket_test bucket::tests::unknown_keys_are_not_refs_and_symlinks_fail_closed
    run_bucket_test bucket::publication::control::tests::activation_staging_accepts_only_its_exact_protected_key
    run_core_bucket_test bucket::keys::tests::protected_delete_operations_require_canonical_cas_keys
    run_core_bucket_test bucket::keys::tests::publication_payload_keys_preserve_mutability_and_control_separation
    run_bucket_test store::native_effect::publication::creation_tests::native_creation_keys_remain_external_and_exactly_associated
    printf 'PASS: bucket-key-registry native layout and pure protected-key conformance\n' > "$out/result"
  '';
  bucket-file-layout = gate "bucket-file-layout" [
    "selection_tests::nested_ref_names_coexist_without_changing_refname_grammar"
    "version_tests::v2_migrated_numbered_log_coexists_with_a_numeric_descendant_ref"
    "version_tests::v2_registered_ref_classes_preserve_public_names_and_reopen"
    "content_tests::portable_copy_reopens_as_the_same_bucket_layout"
    "copy_tests::portable_copy_resolves_exact_projection_and_selected_log_closure"
    "copy_tests::portable_copy_preserves_absent_ref_history_and_recreation"
    "copy_tests::portable_copy_requires_genuine_destination_registration"
    "copy_tests::portable_copy_preserves_burn_visibility_without_old_artifacts"
    "copy_tests::portable_copy_recovers_exact_pending_activation_at_every_boundary"
    "copy_tests::portable_copy_after_interrupted_source_projection_uses_selected_pointer"
    "copy_tests::portable_copy_cancellation_keeps_actual_activation_exclusion"
  ];
  bucket-file-atomic-write = sourceGate "bucket-file-atomic-write" ''
    cd crates
    ${focusedTests}
    run_bucket_test bucket::fault_tests::unsynced_temporary_write_never_changes_visible_ref
    run_bucket_test bucket::fault_tests::partial_generation_is_unpublished_and_retry_uses_a_fresh_generation
    run_bucket_test store::native_effect::tests::directory::restrictive_umask_repairs_the_actual_new_directory_or_refuses_handoff
    run_bucket_test store::native_effect::tests::directory::restored_created_name_rejects_the_opened_directory_decoy
    run_bucket_test store::native_effect::tests::directory::changed_other_projection_after_creation_refuses_mode_repair
    run_bucket_test store::native_effect::tests::directory::failed_parent_sync_never_acknowledges_directory_repair
    run_bucket_test store::native_effect::tests::directory::replacement_after_creation_preserves_the_same_owner_decoy
    run_bucket_test store::native_effect::tests::root_owned_leaf_policy_preserves_actual_operator_ancestor
    ${builtins.concatStringsSep "\n" (map (test: "run_bucket_test store::native_effect::publication::creation_tests::${test}") nativeCreationTests)}
    printf 'PASS: native atomic writes, descriptor-bound private directories and creation journals\n' > "$out/result"
  '';
  bucket-file-cas = gate "bucket-file-cas" (heldContentTests ++ controlFenceTests ++ protectedReadTests ++ ["publication::held_read_tests::record_parent_batches_preserve_entries_duplicates_and_exact_gets" "publication::held_read_tests::record_parent_short_batches_refuse_before_exact_reads_or_effects" "publication::held_read_tests::unsafe_protected_record_parent_precedes_later_missing_parent" "publication::held_read_tests::unsafe_payload_record_parent_precedes_later_metadata_failure" "publication::held_read_tests::payload_parent_batch_final_check_rejects_ancestry_change_after_exact_read" "publication::held_read_tests::short_native_metadata_batch_is_rejected_before_selected_reads_or_effects" "publication::held_read_tests::unsafe_native_ancestor_precedes_later_missing_path_error" "publication::held_read_tests::held_ref_reads_match_ordinary_and_refresh_after_own_publication" "publication::held_read_tests::held_ref_read_rechecks_ancestry_with_unchanged_selected_bytes" "publication::held_read_tests::held_chain_final_check_rejects_real_ancestry_permission_change" "publication::held_read_tests::held_chain_reads_preserve_exact_gets_and_reduce_repeated_metadata" "held_tests::held_buckets_identity_matches_independently_opened_physical_namespace" "version_tests::v2_effects_refuse_changed_version_under_the_actual_root_exclusion" "held_tests::held_buckets_source_readonly_destination_durable_and_independent_reopen" "held_tests::held_buckets_inverse_transactions_finish_in_canonical_order" "held_tests::held_buckets_reject_same_root_and_hardlinked_coordination_inode" "held_tests::held_buckets_cancellation_releases_both_namespace_guards" "held_tests::held_buckets_source_revision_cannot_change_before_destination_cas" "held_tests::held_buckets_cancellation_while_waiting_second_releases_first" "tests::whole_record_cas_has_one_winner_across_independent_opens" "tests::stable_exclusion_inode_survives_cas_and_reopen" "fault_tests::failed_final_cas_sync_requires_authoritative_reread_after_possible_application" "selection_tests::complete_ref_inventory_survives_reopen_index_publication_and_ref_removal" "selection_tests::legacy_unknown_inventory_refuses_unregistered_existing_and_new_advances" "selection_tests::opening_an_existing_empty_root_is_not_fresh_initialization_authority" "fault_tests::first_ref_inventory_is_durable_before_an_indeterminate_head_install" "selection_tests::a_head_missing_from_a_complete_inventory_is_corruption"]);
  bucket-mutability-classes = gate "bucket-mutability-classes" ["tests::tags_and_reflogs_never_replace_existing_bytes" "content_tests::repeated_put_preserves_first_encoding_and_survives_reopen"];
  bucket-create-once = gate "bucket-create-once" ["tests::tags_and_reflogs_never_replace_existing_bytes"];
  bucket-probe = gate "bucket-probe" (activeOpenTests ++ ["fault_tests::startup_refuses_a_binding_that_overwrites_create_once_keys" "tests::probe_revalidates_persisted_layout_and_profile_each_open"]);
  index-generation-manifest = gate "index-generation-manifest" (indexPolicyTests ++ physicalExclusionTests ++ ["retirement_tests::legacy_state1_without_inventory_blocks_opaque_index_aliases_even_with_empty_key6" "retirement_tests::physical_retirement_survives_fresh_readmission_and_exact_restore" "retirement_tests::legacy_unknown_retirement_never_loses_its_last_physical_evidence" "content_tests::manifest_and_every_listed_artifact_are_required_for_generation_visibility" "fault_tests::partial_generation_is_unpublished_and_retry_uses_a_fresh_generation" "container_tests::whole_pack_import_verifies_members_without_admitting_them" "container_tests::quarantine_survives_reopen_and_container_or_body_republication" "manifest_tests::publishing_after_a_legacy_manifest_preserves_existing_bodies" "container_tests::container_inventory_cannot_resurrect_an_excluded_index_identity"]);
}

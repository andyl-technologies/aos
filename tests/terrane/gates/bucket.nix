{sourceGate, ...}: let
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
  '';

  gate = name: tests:
    sourceGate name ''
      cd crates
      ${focusedTests}
      ${builtins.concatStringsSep "\n" (map (test: "run_bucket_test bucket::${test}") tests)}
      printf 'PASS: ${name} native file bucket conformance\n' > "$out/result"
    '';
in {
  store-idempotent-put = gate "store-idempotent-put" ["retirement_tests::physical_exclusion_overrides_live_rows_during_fresh_admission" "content_tests::repeated_put_preserves_first_encoding_and_survives_reopen" "readmission_tests::verified_reupload_replaces_gc_retired_placement_without_restoring_old_pack"];
  store-verify-on-put = gate "store-verify-on-put" ["content_tests::admission_validates_identity_length_profile_and_independent_dedup_context"];
  store-verify-on-get = gate "store-verify-on-get" ["fault_tests::dictionary_backend_unavailability_preserves_put_and_get_failure_kinds" "content_tests::corrupt_bytes_outside_requested_range_are_never_returned"];
  store-ranged-get = gate "store-ranged-get" ["content_tests::ranges_address_verified_encoded_bytes_and_check_overflow"];
  store-has-batched = gate "store-has-batched" ["content_tests::batched_membership_preserves_order_duplicates_and_virtual_empty_chunk"];
  store-ref-cas = gate "store-ref-cas" ["tests::whole_record_cas_has_one_winner_across_independent_opens" "tests::ref_successors_fence_epoch_home_and_sequence" "selection_tests::candidates_bind_the_complete_proposal_and_predecessor_before_head_cas" "selection_tests::independent_candidates_select_one_history_under_concurrent_cas"];
  store-ref-log-append-once = gate "store-ref-log-append-once" ["tests::tags_and_reflogs_never_replace_existing_bytes" "tests::missing_reflog_with_committed_horizon_is_corruption" "tests::committed_reflog_must_match_the_complete_ref_record" "tests::live_watch_waits_for_authoritative_ref_publication_and_replays_sequences" "selection_tests::abandoned_candidates_leave_the_same_sequence_available_to_a_new_writer" "selection_tests::selected_candidates_coexist_with_legacy_numbered_files"];
  store-capability-probe = gate "store-capability-probe" ["tests::probe_revalidates_persisted_layout_and_profile_each_open" "tests::missing_capabilities_never_reinitializes_existing_portable_state"];
  store-list-not-authoritative = gate "store-list-not-authoritative" ["fault_tests::stale_directory_listing_cannot_change_content_or_ref_results"];
  store-validates-uploads = gate "store-validates-uploads" ["fault_tests::dictionary_backend_unavailability_preserves_put_and_get_failure_kinds" "requirement_tests::opaque_metadata_callback_verifies_real_chunks_before_every_dedup" "content_tests::configured_schema_validator_rejects_canonical_but_invalid_meta" "content_tests::admission_validates_identity_length_profile_and_independent_dedup_context" "content_tests::dictionaries_are_fetched_by_verified_chunk_identity_before_decode" "container_tests::whole_pack_import_verifies_members_without_admitting_them" "manifest_tests::manifest_admission_rechecks_nonfinal_context_after_inventory_only_import" "manifest_tests::manifest_references_accept_an_honest_nonfinal_boundary_and_verified_lengths"];
  bucket-key-registry = gate "bucket-key-registry" ["tests::unknown_keys_are_not_refs_and_symlinks_fail_closed"];
  bucket-file-layout = gate "bucket-file-layout" ["content_tests::portable_copy_reopens_as_the_same_bucket_layout"];
  bucket-file-atomic-write = gate "bucket-file-atomic-write" ["fault_tests::unsynced_temporary_write_never_changes_visible_ref" "fault_tests::partial_generation_is_unpublished_and_retry_uses_a_fresh_generation"];
  bucket-file-cas = gate "bucket-file-cas" ["tests::whole_record_cas_has_one_winner_across_independent_opens" "tests::stable_exclusion_inode_survives_cas_and_reopen" "fault_tests::failed_final_cas_sync_requires_authoritative_reread_after_possible_application" "selection_tests::complete_ref_inventory_survives_reopen_index_publication_and_ref_removal" "selection_tests::legacy_unknown_inventory_allows_existing_advances_but_rejects_new_names" "selection_tests::opening_an_existing_empty_root_is_not_fresh_initialization_authority" "fault_tests::first_ref_inventory_is_durable_before_an_indeterminate_head_install" "selection_tests::a_head_missing_from_a_complete_inventory_is_corruption"];
  bucket-mutability-classes = gate "bucket-mutability-classes" ["tests::tags_and_reflogs_never_replace_existing_bytes" "content_tests::repeated_put_preserves_first_encoding_and_survives_reopen"];
  bucket-create-once = gate "bucket-create-once" ["tests::tags_and_reflogs_never_replace_existing_bytes"];
  bucket-probe = gate "bucket-probe" ["fault_tests::startup_refuses_a_binding_that_overwrites_create_once_keys" "tests::probe_revalidates_persisted_layout_and_profile_each_open"];
  index-generation-manifest = gate "index-generation-manifest" ["retirement_tests::physical_exclusion_overrides_live_rows_during_fresh_admission" "retirement_tests::physical_retirement_survives_fresh_readmission_and_exact_restore" "retirement_tests::legacy_unknown_retirement_never_loses_its_last_physical_evidence" "content_tests::manifest_and_every_listed_artifact_are_required_for_generation_visibility" "fault_tests::partial_generation_is_unpublished_and_retry_uses_a_fresh_generation" "container_tests::whole_pack_import_verifies_members_without_admitting_them" "container_tests::quarantine_survives_reopen_and_container_or_body_republication" "manifest_tests::publishing_after_a_legacy_manifest_preserves_existing_bodies" "container_tests::container_inventory_cannot_resurrect_an_excluded_index_identity"];
}

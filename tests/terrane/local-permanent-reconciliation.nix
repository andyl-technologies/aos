{sourceGate}: let
  selectors = [
    "gc::runner::permanent_local_tests::recovery::permanent_local_collection_reconciles_with_its_original_live_session"
    "gc::runner::permanent_local_tests::recovery::permanent_local_pass_reclaims_pack_index_and_all_observed_trash_cycles"
    "gc::runner::permanent_local_tests::recovery::permanent_local_empty_pass_keeps_owner_and_reclaims_late_same_key_residue"
    "gc::runner::permanent_local_tests::recovery::permanent_local_takeover_uses_current_lease_without_replacing_owner"
    "gc::runner::permanent_local_tests::restore::permanent_local_restore_uses_fresh_secure_pack_and_preserves_burn_owner"
    "gc::runner::permanent_local_tests::restore::permanent_local_restore_preserves_fresh_serving_quarantine_and_unrelated_retirement"
    "gc::runner::permanent_local_tests::restore::permanent_local_missing_or_corrupt_source_never_publishes_recovery"
    "gc::runner::permanent_local_tests::faults::permanent_local_replaced_pack_refuses_foreign_unlink"
    "gc::runner::permanent_local_tests::faults::permanent_local_symlink_pack_refuses_foreign_unlink"
    "gc::runner::permanent_local_tests::faults::permanent_local_symlink_trash_cycle_refuses_foreign_unlink"
    "gc::runner::permanent_local_tests::faults::permanent_local_noncanonical_trash_cycle_refuses_foreign_unlink"
    "gc::runner::permanent_local_tests::faults::permanent_local_foreign_hardlink_refuses_unlink"
    "gc::runner::permanent_local_tests::faults::permanent_local_queued_lease_expiry_refuses_new_requests"
    "gc::runner::permanent_local_tests::faults::permanent_local_queued_original_replacement_refuses_new_requests"
    "gc::runner::permanent_local_tests::faults::permanent_local_queued_backend_registration_replacement_refuses_new_requests"
    "gc::runner::permanent_local_tests::faults::permanent_local_queued_data_replacement_refuses_new_requests"
    "gc::runner::permanent_local_tests::faults::permanent_local_before_unlink_failure_keeps_selected_recovery_duties"
    "gc::runner::permanent_local_tests::faults::permanent_local_after_unlink_failure_keeps_selected_recovery_duties"
    "gc::runner::permanent_local_tests::faults::permanent_local_directory_sync_failure_keeps_selected_recovery_duties"
    "gc::runner::permanent_local_tests::faults::permanent_local_progress_sync_failure_keeps_selected_recovery_duties"
    "gc::runner::permanent_local_tests::faults::permanent_local_cancelled_waiter_before_open_retains_exclusion_through_worker_completion"
    "gc::runner::permanent_local_tests::faults::permanent_local_cancelled_waiter_before_directory_sync_retains_exclusion_through_worker_completion"
    "gc::runner::permanent_local_tests::faults::permanent_local_cancelled_waiter_after_directory_sync_retains_exclusion_through_worker_completion"
    "gc::runner::permanent_local_tests::faults::permanent_local_progress_conflict_retains_owner_and_uses_fresh_event_nonce"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_requested_directory_replacement_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_requested_directory_policy_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_off_batch_policy_refuses_before_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_added_cycle_keeps_late_residue_unselected"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_removed_cycle_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_noncanonical_cycle_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_symlink_cycle_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_expired_whole_lease_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_replaced_owner_preimage_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_replaced_original_preimage_refuses_selection"
    "gc::runner::permanent_local_tests::recovery::staging::permanent_local_staging_cancellation_keeps_proposals_unselected_after_reopen"
  ];
  runCases = import ./_native-cases.nix {
    label = "local-permanent-reconciliation";
    inherit selectors;
  };
in
  # This auxiliary check covers permanent local recovery. Full two-phase GC
  # and provider qualification still require their complete owning gate sets.
  sourceGate "local-permanent-reconciliation" ''
    ${runCases}
    printf 'PASS: permanent local recovery and fresh-placement restore (35 exact cases)\n' \
      > "$out/result"
  ''

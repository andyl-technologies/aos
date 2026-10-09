{sourceGate}: let
  selectors = [
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
  ];
in
  # This auxiliary check covers permanent local recovery. Full two-phase GC
  # and provider qualification still require their complete owning gate sets.
  sourceGate "local-permanent-reconciliation" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/permanent-local-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/permanent-local-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/permanent-local-test.log" 2>&1; then
        cat "$TMPDIR/permanent-local-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/permanent-local-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: permanent local recovery and fresh-placement restore (23 exact cases)\n' \
      > "$out/result"
  ''

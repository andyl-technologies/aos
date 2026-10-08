{sourceGate}: let
  names = [
    "success::full_d_and_current_lease_unlink_exact_triple_and_finish_done"
    "success::fresh_readmission_survives_old_container_deletion_and_reopen"
    "recovery::fresh_higher_epoch_resumes_each_real_durable_prefix_without_old_marks"
    "recovery::owned_absence_resynchronizes_before_phase_and_done_is_idempotent"
    "faults::each_unlink_directory_and_progress_sync_fault_preserves_exact_recoverable_prefix"
    "faults::each_handoff_refuses_current_expiry_control_change_and_replacement"
    "faults::unit_success_or_swallowed_sync_failure_never_acknowledges_progress"
    "recovery::cancelled_waiter_retains_exclusion_until_worker_then_fresh_collector_finishes"
    "recovery::changed_current_fence_reconciles_retained_index_after_container_absence"
    "recovery::restore_durably_cancels_exact_local_owner_before_clearing_exclusion"
    "recovery::missing_trash_crash_requires_fresh_retirement_and_full_d_before_done"
  ];
  selectors = map (name: "gc::runner::tests::local_deletion::${name}") names;
in
  # These cases cover ordinary local-v1 deletion and recovery. Remote permanent
  # ownership and copied retirement retain their separately specified protocol.
  sourceGate "native-local-deletion" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/local-deletion-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/local-deletion-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/local-deletion-test.log" 2>&1; then
        cat "$TMPDIR/local-deletion-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/local-deletion-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: eleven exact ordinary local-v1 deletion and recovery cases\n' > "$out/result"
  ''

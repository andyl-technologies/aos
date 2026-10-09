{sourceGate}: let
  selectors = [
    "gc::copied_retirement_effects::pair_bracketing_tests::collector_pairs_refuse_earlier_replacement_during_later_native_observation"
    "gc::copied_retirement_effects::pair_bracketing_tests::collector_pairs_cancelled_later_worker_keeps_earlier_receipt_and_exclusion"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_pack_only_selects_new_destination_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_index_only_selects_new_destination_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_trash_only_selects_new_destination_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_all_absent_selects_new_destination_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_missing_foreign_original_keeps_complete_live_data"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_unresolved_live_data_refuses_before_preparation"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_incomplete_ref_or_absent_history_refuses_preparation"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_burned_or_excluded_fallback_cannot_cover_live_data"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_new_barrier_journal_precedes_full_g_and_d"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_same_holder_renewal_preserves_barrier_wait"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_queued_whole_lease_change_or_expiry_refuses_owner"
    "gc::runner::copied_retirement_tests::cadence::gc_copied_retirement_native_skipped_renewal_whole_lease_change_refuses_owner"
    "gc::runner::copied_retirement_tests::cadence::gc_copied_retirement_native_skipped_renewal_guard_change_refuses_owner"
    "gc::runner::copied_retirement_tests::cadence::gc_copied_retirement_native_skipped_renewal_expiry_or_clock_regression_refuses_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_changed_guard_or_consumed_control_refuses_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_replaced_barrier_or_clock_regression_resets_wait"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_reopen_restarts_full_same_clock_wait"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_takeover_selects_fresh_preparation_and_barrier"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_barrier_collision_preserves_old_trash"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_losing_preparation_cannot_create_barrier"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_failed_or_unexecuted_native_ack_cannot_select_owner"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_first_owner_drops_unqualified_lineage_and_keeps_burns"
    "gc::runner::copied_retirement_tests::gc_copied_retirement_native_unused_memo_sharing_live_index_result_keeps_actual_context"
  ];
in
  # This check covers local copied-destination first ownership. Recurring
  # recovery and provider-specific qualification remain separate obligations.
  sourceGate "native-copied-retirement-first-ownership" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/copied-retirement-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/copied-retirement-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/copied-retirement-test.log" 2>&1; then
        cat "$TMPDIR/copied-retirement-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/copied-retirement-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: local copied-destination first ownership and retained-pair prerequisites (25 exact cases)\n' \
      > "$out/result"
  ''

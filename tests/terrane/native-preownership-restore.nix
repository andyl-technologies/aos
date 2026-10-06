{sourceGate}: let
  tests = [
    "gc_restore_native_unknown_trash_age_restores_exact_generation"
    "gc_restore_native_preserves_fresh_live_quarantine_and_selected_values"
    "gc_restore_native_stale_and_unknown_incarnations_never_publish"
    "gc_restore_native_missing_pair_never_advertises_old_placement"
    "gc_restore_native_burn_owner_and_deleteowned_refuse"
    "gc_restore_native_metadata_only_pair_handles_imported_unknown"
    "gc_restore_native_each_handoff_rechecks_current_controls_and_pair"
    "gc_restore_native_sync_and_noop_results_never_acknowledge"
    "gc_restore_native_cancelled_worker_retains_exclusions"
    "gc_restore_native_reopen_and_fresh_cycle_make_old_trash_stale"
  ];
  selectors = map (name: "gc::runner::tests::restore::${name}") tests;
in
  sourceGate "native-preownership-restore" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/restore-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/restore-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/restore-test.log" 2>&1; then
        cat "$TMPDIR/restore-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/restore-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: native pre-ownership restore (10 exact cases); two-phase deletion remains separate\n' \
      > "$out/result"
  ''

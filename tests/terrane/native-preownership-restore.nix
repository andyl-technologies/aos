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
    python3 - "$TMPDIR/restore-tests.txt" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    required = ${builtins.toJSON selectors}
    if len(required) != len(set(required)):
        raise SystemExit("duplicate required restore test")

    missing = [name for name in required if f"{name}: test" not in names]
    if missing:
        raise SystemExit(f"required native restore tests are missing: {missing}")
    PYTEST
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact
    done
    printf 'PASS: native pre-ownership restore (10 exact cases); two-phase deletion remains separate\n' \
      > "$out/result"
  ''

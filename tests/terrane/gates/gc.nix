{sourceGate, ...}: let
  nativeTests = [
    "gc::lease::tests::native_gc_independent_collectors_have_one_selected_winner"
    "gc::lease::tests::native_gc_renewal_uses_exact_whole_value_and_increases_revision"
    "gc::lease::tests::native_gc_live_other_holder_refuses_without_cache_repair_or_effects"
    "gc::lease::tests::native_gc_expired_lease_takeover_selects_a_higher_epoch"
    "gc::lease::tests::native_gc_queued_expiry_refuses_before_selected_slot_syscall"
    "gc::lease::tests::native_gc_queued_consumed_control_change_refuses_before_syscall"
    "gc::lease::tests::native_gc_queued_predecessor_change_refuses_before_syscall"
    "gc::lease::tests::native_gc_cancelled_waiter_retains_all_exclusions_through_slot_sync"
    "gc::lease::tests::native_gc_queued_renewal_requires_the_original_expiry_to_remain_live"
    "gc::lease::tests::native_gc_queued_clock_discontinuity_refuses_before_syscall"
    "gc::lease::tests::native_gc_stale_configured_guard_refuses_without_effects"
    "gc::lease::tests::native_gc_existing_open_does_not_recreate_coordination_or_control"
    "gc::lease::tests::native_gc_final_selection_ack_requires_current_retained_clock"
    "gc::runner::tests::gc_native_published_roots_mark_finish_and_resume"
    "gc::runner::tests::gc_native_stale_runner_renewal_stops_before_checkpoint_effects"
    "gc::runner::tests::gc_native_canceled_checkpoint_keeps_exclusion_and_poisons_session"
    "gc::runner::tests::gc_native_queued_checkpoint_rechecks_actual_expiry_and_never_acknowledges"
    "gc::runner::tests::gc_native_takeover_refuses_old_mark_epoch_and_completes_new_cycle"
  ];

  localTests = [
    "gc::lease::local_tests::native_gc_rc_bindings_acquire_renew_take_over_and_reopen"
  ];

  # An exact filter with no matching test succeeds in Cargo. Validate the whole
  # required inventory before running each actual case in its own process.
  focusedTests = features: tests: ''
    cargo test --frozen --offline -p terrane --no-default-features \
      --features ${features} --lib -- --list > "$TMPDIR/gc-tests.txt"
    python3 - "$TMPDIR/gc-tests.txt" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    required = ${builtins.toJSON tests}
    if len(required) != len(set(required)):
        raise SystemExit("duplicate required collector test")

    missing = [name for name in required if f"{name}: test" not in names]
    if missing:
        raise SystemExit(f"required collector tests are missing: {missing}")
    PYTEST
    for test_name in ${builtins.concatStringsSep " " tests}; do
      cargo test --frozen --offline -p terrane --no-default-features \
        --features ${features} --lib "$test_name" -- --exact
    done
  '';
in {
  gc-singleton-lease = sourceGate "gc-singleton-lease" ''
    cd crates
    ${focusedTests "tokio,surface-sdk" nativeTests}
    ${focusedTests "std,surface-sdk" localTests}
    printf 'PASS: selected singleton lease, runner fencing, takeover and non-Send bindings (19 exact cases)\n' \
      > "$out/result"
  '';
}

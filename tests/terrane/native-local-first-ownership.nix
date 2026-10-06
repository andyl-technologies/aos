{sourceGate}: let
  tests = [
    "waits::full_d_with_multiple_real_renewals_reaches_invalidated"
    "waits::early_and_expired_wait_never_create_authorized"
    "waits::regression_or_changed_incarnation_discards_wait"
    "waits::renewal_failure_and_dropped_wait_poison_session"
    "ownership::authorized_and_each_owner_sync_fault_preserve_exact_partial_prefix"
    "ownership::fresh_current_authority_required_before_each_ownership_effect"
  ];
  selectors = map (name: "gc::runner::tests::local_ownership::${name}") tests;
in
  sourceGate "native-local-first-ownership" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/local-ownership-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/local-ownership-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/local-ownership-test.log" 2>&1; then
        cat "$TMPDIR/local-ownership-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/local-ownership-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: ordinary local first ownership (6 exact cases); unlink/recovery/cancellation remain separate\n' \
      > "$out/result"
  ''

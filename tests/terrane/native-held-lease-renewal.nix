{sourceGate}: let
  tests = [
    "held_renewal_reuses_actual_namespace_and_controls"
    "held_renewal_requires_exact_live_whole_lease"
    "held_renewal_acknowledges_only_actual_durable_success"
    "held_renewal_preserves_clock_continuity_and_old_expiry"
    "held_renewal_refreshes_only_acknowledged_lease_selection"
    "held_renewal_cancellation_retains_exclusion_and_poisoning"
  ];
  selectors = map (name: "gc::lease::held_tests::${name}") tests;
in
  sourceGate "native-held-lease-renewal" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/held-renewal-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/held-renewal-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/held-renewal-test.log" 2>&1; then
        cat "$TMPDIR/held-renewal-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/held-renewal-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: retained-context lease renewal (6 exact cases); deletion ownership remains separate\n' \
      > "$out/result"
  ''

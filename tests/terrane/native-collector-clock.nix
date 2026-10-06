{sourceGate}: let
  tests = [
    "manual_collector_clock_keeps_sleep_unsupported"
    "retained_collector_timer_advances_the_same_clock"
    "collector_timer_exposes_regression_and_dropped_sleep"
  ];
  selectors = map (name: "store::native_clock::tests::${name}") tests;
in
  sourceGate "native-collector-clock" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/collector-clock-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/collector-clock-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/collector-clock-test.log" 2>&1; then
        cat "$TMPDIR/collector-clock-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/collector-clock-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: retained collector test clock (3 exact cases)\n' > "$out/result"
  ''

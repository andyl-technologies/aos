{sourceGate}: let
  names = [
    "recorded_disclosure_completes_actual_history_and_context"
    "recorded_disclosure_refuses_missing_or_wrong_original_associations"
    "recorded_disclosure_requires_complete_dependencies_and_exact_current_fence"
    "recorded_disclosure_keeps_original_roles_and_current_read_independent"
  ];
  selectors = map (name: "guard::history::disclosure::recorded::tests::${name}") names;
in
  # This prerequisite verifies completed historical disclosure. Fresh Recorded
  # candidate admission, index completion and cold carry keep their own gates.
  sourceGate "native-recorded-disclosure" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/recorded-disclosure-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/recorded-disclosure-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/recorded-disclosure-test.log" 2>&1; then
        cat "$TMPDIR/recorded-disclosure-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/recorded-disclosure-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: four exact native Recorded historical-disclosure cases\n' > "$out/result"
  ''

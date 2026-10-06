{sourceGate}: let
  tests = [
    "checked_mutation_acknowledges_actual_guard_and_ref_publication"
    "checked_mutation_denies_noop_unit_success"
    "checked_mutation_denies_swallowed_sync_failures"
    "checked_mutation_retains_selected_guard_and_control_preimages"
    "checked_mutation_cancellation_retains_actual_exclusions"
    "checked_mutation_refreshes_before_actual_directory_sync"
  ];
  selectors = map (name: "ref_advance::fault_tests::mutation_ack::${name}") tests;
in
  sourceGate "native-checked-mutation-publication" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/mutation-ack-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/mutation-ack-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/mutation-ack-test.log" 2>&1; then
        cat "$TMPDIR/mutation-ack-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/mutation-ack-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: actual checked Guard/ref publication acknowledgment (6 exact cases)\n' \
      > "$out/result"
  ''

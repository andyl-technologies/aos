{sourceGate}: let
  tests = [
    "real_node_reads_share_clone_and_held_decoder_observation"
    "missing_node_attempt_precedes_body_decode_and_is_fixture_local"
    "deduplicated_node_puts_remain_observable_attempts"
  ];
  selectors = map (name: "bucket::content_observation::tests::${name}") tests;
in
  sourceGate "native-content-observation" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/content-observation-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/content-observation-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/content-observation-test.log" 2>&1; then
        cat "$TMPDIR/content-observation-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/content-observation-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: native typed content observation calibration (3 exact cases)\n' \
      > "$out/result"
  ''

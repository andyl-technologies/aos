{sourceGate}: let
  prefix = "selected_bridge::native_guard::cold_fork::tests::publication::";
  nativeNames = [
    "root_native_cold_fork_publishes_fresh_signed_namespace_without_nodes"
    "root_native_cold_fork_reuses_after_unrelated_ref_admission"
    "root_native_cold_fork_refuses_absent_context_before_node_io"
    "root_native_cold_fork_after_separate_same_head_requalification"
    "root_native_cold_fork_refuses_current_source_and_destination_rights"
    "root_native_cold_fork_refuses_changed_original_and_selected_controls"
    "root_native_cold_fork_rejects_profile_and_occurrence_contradictions"
  ];
  nativeSelectors = map (name: "${prefix}${name}") nativeNames;
  sendSelector = "${prefix}root_native_cold_fork_stops_on_sync_failure_and_expiry";
in
  sourceGate "native-cold-fork-legacy" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/cold-legacy-native-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/cold-legacy-native-tests.txt" '${builtins.toJSON nativeSelectors}'
    for test_name in ${builtins.concatStringsSep " " nativeSelectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/cold-legacy-test.log" 2>&1; then
        cat "$TMPDIR/cold-legacy-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/cold-legacy-test.log" "[\"$test_name\"]"
    done
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk,send --lib -- --list > "$TMPDIR/cold-legacy-send-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/cold-legacy-send-tests.txt" '["${sendSelector}"]'
    if ! cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk,send --lib '${sendSelector}' -- --exact \
      > "$TMPDIR/cold-legacy-test.log" 2>&1; then
      cat "$TMPDIR/cold-legacy-test.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$TMPDIR/cold-legacy-test.log" '["${sendSelector}"]'
    printf 'PASS: supported local Legacy cold fork (8 exact cases)\n' > "$out/result"
  ''

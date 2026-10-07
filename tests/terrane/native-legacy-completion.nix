{sourceGate}: let
  tests = [
    "native_legacy_completion_retains_every_signed_parent_context"
    "native_legacy_completion_refuses_required_index_without_selected_ack"
    "native_legacy_completion_checks_each_signed_requirement_field"
    "native_legacy_completion_refuses_historical_binding_with_empty_head_index"
    "native_legacy_completion_late_original_failure_promotes_no_views"
  ];
  selectors = map (name: "ref_advance::legacy_completion_tests::${name}") tests;
in
  sourceGate "native-legacy-completion" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/legacy-completion-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/legacy-completion-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/legacy-completion-test.log" 2>&1; then
        cat "$TMPDIR/legacy-completion-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/legacy-completion-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: owning local Legacy signed-history completion (5 exact cases)\n' \
      > "$out/result"
  ''

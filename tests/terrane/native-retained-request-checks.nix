{sourceGate}: let
  tests = [
    "retained_scalar_checks_match_full_verification_across_current_times"
    "retained_issuer_selection_preserves_retirement_and_duplicate_clock_rollback"
    "retained_caveats_reauthorize_exact_request_context"
    "retained_locality_matches_full_scalar_authorization"
    "retained_factory_reauthenticates_bytes_and_preserves_refusal"
    "retained_deadline_rechecks_same_clock_and_preserves_uniform_denial"
    "retained_clock_retention_refusal_precedes_empty_requests"
  ];
  selectors = map (name: "guard::time::tests::${name}") tests;
in
  sourceGate "native-retained-request-checks" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/retained-request-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/retained-request-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/retained-request-test.log" 2>&1; then
        cat "$TMPDIR/retained-request-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/retained-request-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: retained authentication with fresh request checks (7 exact cases)\n' \
      > "$out/result"
  ''

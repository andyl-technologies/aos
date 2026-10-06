{sourceGate}: let
  names = [
    "native_index_lookup_matches_sha256_and_deduplicates_authorized_occurrences"
    "native_index_lookup_filters_current_acl_trust_and_producer_context"
    "native_index_lookup_reports_gaps_even_when_candidate_range_is_empty"
    "native_index_lookup_selects_fallback_only_without_owner_binding"
    "native_index_lookup_rechecks_held_current_controls_before_return"
    "native_index_lookup_separates_loading_validation_candidates_occurrences_and_current_work"
  ];
  selectors = map (name: "guard::read::indexes::tests::${name}") names;
in
  # Indexed candidates remain data until actual current checks produce answers.
  sourceGate "native-index-lookup" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/index-lookup-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/index-lookup-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/index-lookup-test.log" 2>&1; then
        cat "$TMPDIR/index-lookup-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/index-lookup-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: six exact native authorized index-lookup prerequisites\n' > "$out/result"
  ''

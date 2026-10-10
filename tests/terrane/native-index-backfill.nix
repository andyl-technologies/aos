{sourceGate}: let
  names = [
    "native_index_backfill_reuses_checked_side_value_without_plaintext_reads"
    "native_index_backfill_reports_unavailable_or_invalid_evidence_as_gaps"
    "native_index_backfill_rechecks_producer_current_and_final_publication"
    "native_index_backfill_closes_required_inline_and_index_gaps_in_real_commit"
    "native_index_backfill_preserves_complete_carriers_after_protected_reopen"
    "native_index_backfill_updates_existing_required_binding_in_real_commit"
  ];
  selectors = map (name: "guard::index_backfill::tests::${name}") names;
in
  # Checked side-record reuse still requires actual inline and owner completion.
  sourceGate "native-index-backfill" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/index-backfill-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/index-backfill-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/index-backfill-test.log" 2>&1; then
        cat "$TMPDIR/index-backfill-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/index-backfill-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: ${toString (builtins.length selectors)} exact native checked side-record backfill cases\n' > "$out/result"
  ''

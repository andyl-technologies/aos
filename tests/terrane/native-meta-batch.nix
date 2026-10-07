{sourceGate}: let
  tests = [
    "native_meta_batch_selects_one_genuine_pair_for_distinct_validated_members"
    "native_meta_batch_validates_duplicates_and_preserves_existing_and_empty_runs"
    "native_meta_batch_preserves_direct_container_and_actual_repair_fallback"
    "native_meta_batch_creator_and_catalog_errors_never_acknowledge_members"
    "native_meta_batch_rechecks_current_original_and_deadline_before_ack"
    "native_meta_batch_cancelled_and_partial_runs_keep_native_receipts_honest"
  ];
  selectors = map (name: "ref_advance::meta_batch_tests::${name}") tests;
in
  sourceGate "native-meta-batch" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/meta-batch-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/meta-batch-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/meta-batch-test.log" 2>&1; then
        cat "$TMPDIR/meta-batch-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/meta-batch-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: ordinary native immutable Meta batching (6 exact cases)\n' \
      > "$out/result"
  ''

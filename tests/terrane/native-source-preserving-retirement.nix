{sourceGate}: let
  names = [
    "source_preserving_retirement_carries_complete_view_contexts_to_new_loss_generation"
    "cold_fork_after_source_preserving_retirement_reads_zero_tree_nodes"
    "witness_only_selected_source_requires_complete_ordinary_visit_before_carry"
    "changed_selected_source_original_or_interpretation_refuses_stale_carry"
    "removed_index_marked_member_prevents_source_preserving_retirement"
    "lineage_stage_or_native_sync_failure_never_acknowledges_partial_carry"
  ];
  selectors = map (name: "gc::runner::tests::source_carry::${name}") names;
in
  # A complete ordinary source walk and real retirement must precede cold reuse.
  sourceGate "native-source-preserving-retirement" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/source-carry-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/source-carry-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/source-carry-test.log" 2>&1; then
        cat "$TMPDIR/source-carry-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/source-carry-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: six exact native source-preserving retirement prerequisites\n' > "$out/result"
  ''

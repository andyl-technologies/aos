{sourceGate}: let
  tests = [
    "written_mutation_syncs_exact_outputs_and_unique_directories"
    "written_mutation_syncs_unchanged_projection_repair"
    "written_mutation_syncs_removed_projection_cache_directory"
    "written_mutation_syncs_newly_created_projection_directories"
    "written_mutation_retains_unsynchronized_history_preimages"
    "written_mutation_retains_unsynchronized_source_lineage_preimage"
  ];
  selectors = map (name: "ref_advance::fault_tests::mutation_ack::write_set::${name}") tests;
in
  sourceGate "native-written-mutation-sync" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/written-mutation-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/written-mutation-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      test_log="$TMPDIR/$test_name.log"
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$test_log" 2>&1; then
        cat "$test_log"
        exit 1
      fi
      cat "$test_log"
      python3 ../tests/terrane/check_native_gate.py execution \
        "$test_log" "[\"$test_name\"]"
    done
    printf 'PASS: actual written mutation durability (6 exact cases)\n' > "$out/result"
  ''

{sourceGate}: let
  nativeNames = [
    "native_index_propagation_selects_only_affected_immutable_graft_entries"
    "native_index_propagation_preserves_repeated_grafts_and_conflict_refusal"
    "native_index_propagation_keeps_preparation_outside_delta_and_boundary_work"
  ];
  pureNames = [
    "prepared_graft_targets_batch_conflict_candidates_and_present_base"
    "prepared_graft_targets_keep_repeated_occurrences_and_skip_equal_targets"
    "prepared_graft_targets_refuse_inconsistent_owned_lookup_inputs"
  ];
  selectors =
    map (name: "guard::authoring::tests::publication::locality::${name}") nativeNames
    ++ map (name: "guard::admission::index_writer::propagation::tests::${name}") pureNames;
in
  # Exhaustive canonical output checks run outside the measured maintenance.
  sourceGate "native-index-locality" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/index-locality-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/index-locality-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/index-locality-test.log" 2>&1; then
        cat "$TMPDIR/index-locality-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/index-locality-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: three native graft locality and three structural cases; full preparation charged separately\n' > "$out/result"
  ''

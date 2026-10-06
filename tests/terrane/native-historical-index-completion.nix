{sourceGate}: let
  names = [
    "historical_index_completion_validates_real_signed_owner_and_full_carriers"
    "historical_index_completion_preserves_repeated_occurrence_policy_contexts"
    "historical_index_completion_refuses_divergent_or_incomplete_relationships"
    "historical_index_completion_keeps_missing_binding_and_conflict_incomplete"
    "historical_index_completion_uses_independently_installed_attribute_profile"
    "historical_index_completion_rechecks_full_profile_only_after_history_finish"
    "historical_index_completion_loads_exact_staged_and_stored_nodes_read_only"
    "historical_index_completion_validates_structural_placement_without_requirements"
  ];
  selectors = map (name: "guard::history::completion::indexes::tests::${name}") names;
in
  # This prerequisite verifies immutable historical relationships and actual
  # interpretation inputs. Selected publication and maintenance keep their gates.
  sourceGate "native-historical-index-completion" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/historical-index-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/historical-index-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/historical-index-test.log" 2>&1; then
        cat "$TMPDIR/historical-index-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/historical-index-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: eight exact native historical-index completion cases\n' > "$out/result"
  ''

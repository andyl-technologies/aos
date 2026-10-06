{sourceGate}: let
  names = [
    "authoring_attribute_two_is_selected_before_candidate_signing"
    "selected_required_index_publishes_real_context_and_full_carriers"
    "selected_required_index_refuses_divergence_before_immutable_effects"
    "selected_required_index_preserves_old_inert_historical_profiles"
    "selected_required_index_distinguishes_preserved_gaps_and_dropped_bindings"
    "selected_required_index_policy_and_rollback_retain_actual_view_selection"
    "selected_required_index_adapter_and_reopen_keep_installed_inputs"
    "selected_required_index_refuses_existing_guard_profile_replacement"
  ];
  selectors = map (name: "guard::authoring::tests::${name}") names;
in
  # Admission must select its actual inputs before signing and retain them
  # through publication. This prerequisite does not certify incremental work.
  sourceGate "native-index-publication" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/index-publication-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/index-publication-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/index-publication-test.log" 2>&1; then
        cat "$TMPDIR/index-publication-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/index-publication-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: eight exact native index-publication cases\n' > "$out/result"
  ''

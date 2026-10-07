{sourceGate}: let
  tests = [
    "reopened_selected_source_qualifies_without_node_or_pack_body_io"
    "qualified_source_rechecks_original_loss_and_live_expiry"
    "newly_selected_source_acl_revocation_denies_cold_fork"
    "raw_alias_of_signed_source_has_no_cold_qualification"
    "altered_protected_lineage_cannot_qualify_source_policies"
    "repeated_root_occurrences_keep_independent_current_caveat_checks"
  ];
  publicationTests = [
    "repository_fork_publishes_fresh_signed_commit_without_node_io"
    "cold_reuse_refuses_absent_or_changed_per_view_interpretation_inputs"
    "final_cold_dispatch_refuses_source_original_lost_after_preparation"
    "repository_raw_source_uses_ordinary_full_admission"
    "repository_selected_source_propagates_current_fork_denial_without_fallback"
    "repository_older_lineage_requalifies_before_separate_zero_node_fork"
  ];
  selectors =
    map (name: "selected_bridge::native_guard::cold_fork::tests::${name}") tests
    ++ map (name: "selected_bridge::native_guard::cold_fork::tests::publication::${name}") publicationTests
    ++ ["guard::original::verifier::cold::tests::abandoned_routes_are_pruned_without_evicting_live_attempts"];
in
  sourceGate "native-cold-fork-source" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/cold-fork-source-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/cold-fork-source-tests.txt" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/cold-fork-source-test.log" 2>&1; then
        cat "$TMPDIR/cold-fork-source-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/cold-fork-source-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: native cold-fork source and publication prerequisites (13 exact cases); source-preserving collection remains separate\n' \
      > "$out/result"
  ''

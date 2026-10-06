{sourceGate}: let
  tests = [
    "reopened_selected_source_qualifies_without_node_or_pack_body_io"
    "qualified_source_rechecks_original_loss_and_live_expiry"
    "newly_selected_source_acl_revocation_denies_cold_fork"
    "raw_alias_of_signed_source_has_no_cold_qualification"
    "altered_protected_lineage_cannot_qualify_source_policies"
    "repeated_root_occurrences_keep_independent_current_caveat_checks"
  ];
  selectors = map (name: "selected_bridge::native_guard::cold_fork::tests::${name}") tests;
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
    printf 'PASS: native cold-fork source qualification (6 exact cases); end-to-end fork remains separate\n' \
      > "$out/result"
  ''

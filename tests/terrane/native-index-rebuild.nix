{sourceGate}: let
  names = [
    "native_index_verify_reports_divergence_without_mutation"
    "native_index_rebuild_recovers_divergent_and_missing_auxiliary_closures"
    "native_index_rebuild_rechecks_original_current_producer_and_final_ack"
    "native_index_recovery_refuses_authority_changed_after_durable_replacement"
    "native_index_recovery_preserves_original_deadline_across_replacement"
    "native_index_recovery_refuses_stale_whole_ref_after_actual_repair"
  ];
  selectors = map (name: "guard::index_maintenance::tests::${name}") names;
in
  # Immutable rebuild data must cross the genuine current publication boundary.
  sourceGate "native-index-rebuild" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/index-rebuild-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/index-rebuild-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/index-rebuild-test.log" 2>&1; then
        cat "$TMPDIR/index-rebuild-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/index-rebuild-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: six exact native checked index verification and rebuild cases\n' > "$out/result"
  ''

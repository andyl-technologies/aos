{sourceGate}: let
  selectors = [
    "selected_bridge::native_guard::cold_fork::tests::publication::repository_raw_source_uses_ordinary_full_admission"
    "selected_bridge::native_guard::cold_fork::tests::publication::repository_older_lineage_requalifies_before_separate_zero_node_fork"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::requalification_byte_identical_context_refuses_fresh_ack"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::requalification_preserves_current_fork_and_token_refusals"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::requalification_refuses_malformed_selected_lineage"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_original_loss_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_source_record_replacement_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_selected_log_replacement_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_control_permission_change_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_token_expiry_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::faults::requalification_refuses_native_sync_without_ack"
    "selected_bridge::native_guard::cold_fork::tests::publication::requalification::indexes::requalification_refuses_actual_required_index_read_failure"
  ];
in
  # Full completion is a separate acknowledged operation before the cold fork.
  sourceGate "native-source-requalification" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/source-requalification-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/source-requalification-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/source-requalification-test.log" 2>&1; then
        cat "$TMPDIR/source-requalification-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/source-requalification-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: twelve exact separate source requalification and refusal cases\n' > "$out/result"
  ''

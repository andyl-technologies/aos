{sourceGate}: let
  selectors = [
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::repository_raw_source_requalifies_before_separate_zero_node_fork"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::repository_older_lineage_requalifies_before_separate_zero_node_fork"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::requalification_byte_identical_context_refuses_fresh_ack"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::requalification_preserves_current_fork_and_token_refusals"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::requalification_refuses_malformed_selected_lineage"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_original_loss_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_source_record_replacement_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_selected_log_replacement_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_control_permission_change_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_token_expiry_at_lineage_install"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::faults::requalification_refuses_native_sync_without_ack"
    "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::requalification::indexes::requalification_refuses_actual_required_index_read_failure"
  ];
  runCases = import ./_native-cases.nix {
    label = "native-source-requalification";
    inherit selectors;
  };
in
  # Full completion is a separate acknowledged operation before the cold fork.
  sourceGate "native-source-requalification" ''
    ${runCases}
    printf 'PASS: twelve exact separate source requalification and refusal cases\n' > "$out/result"
  ''

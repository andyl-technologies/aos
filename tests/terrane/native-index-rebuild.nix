{sourceGate}: let
  names = [
    "native_repeated_producer_checks_preserve_current_and_original_refusal"
    "native_index_verify_reports_divergence_without_mutation"
    "native_index_rebuild_recovers_divergent_and_missing_auxiliary_closures"
    "native_index_rebuild_rechecks_original_current_producer_and_final_ack"
    "native_index_recovery_refuses_authority_changed_after_durable_replacement"
    "native_index_recovery_preserves_original_deadline_across_replacement"
    "native_index_recovery_refuses_stale_whole_ref_after_actual_repair"
  ];
  selectors = map (name: "guard::index_maintenance::tests::${name}") names;
  runCases = import ./_native-cases.nix {
    label = "native-index-rebuild";
    inherit selectors;
  };
in
  # Immutable rebuild data must cross the genuine current publication boundary.
  sourceGate "native-index-rebuild" ''
    ${runCases}
    printf 'PASS: seven exact native checked index verification and rebuild cases\n' > "$out/result"
  ''

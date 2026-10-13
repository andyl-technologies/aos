{sourceGate}: let
  names = [
    "native_index_backfill_reuses_checked_side_value_without_plaintext_reads"
    "native_index_backfill_reports_unavailable_or_invalid_evidence_as_gaps"
    "native_index_backfill_rechecks_producer_current_and_final_publication"
    "native_index_backfill_closes_required_inline_and_index_gaps_in_real_commit"
    "native_index_backfill_preserves_complete_carriers_after_protected_reopen"
    "native_index_backfill_updates_existing_required_binding_in_real_commit"
  ];
  selectors = map (name: "guard::index_backfill::tests::${name}") names;
  runCases = import ./_native-cases.nix {
    label = "native-index-backfill";
    inherit selectors;
  };
in
  # Checked side-record reuse still requires actual inline and owner completion.
  sourceGate "native-index-backfill" ''
    ${runCases}
    printf 'PASS: ${toString (builtins.length selectors)} exact native checked side-record backfill cases\n' > "$out/result"
  ''

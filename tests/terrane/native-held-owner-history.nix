{sourceGate}: let
  selectors = [
    "guard::held_history::tests::held_owner_history_preserves_original_purpose_and_baseline_selection"
    "guard::held_history::tests::held_owner_history_checks_each_authorization_with_scoped_pack_reads"
    "guard::held_history::tests::held_owner_history_closes_all_physical_and_current_inputs"
    "guard::held_history::tests::held_owner_history_cancellation_and_native_decline_preserve_failure"
  ];
  runCases = import ./_native-cases.nix {
    label = "native-held-owner-history";
    inherit selectors;
  };
in
  sourceGate "native-held-owner-history" ''
    ${runCases}
    printf 'PASS: four exact held owner-history purpose and closing cases\n' > "$out/result"
  ''

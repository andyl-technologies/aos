{sourceGate}: let
  tests = [
    "checked_mutation_acknowledges_actual_guard_and_ref_publication"
    "checked_mutation_denies_noop_unit_success"
    "checked_mutation_denies_swallowed_sync_failures"
    "checked_mutation_retains_selected_guard_and_control_preimages"
    "checked_mutation_cancellation_retains_actual_exclusions"
    "checked_mutation_refreshes_before_actual_directory_sync"
  ];
  selectors = map (name: "ref_advance::fault_tests::mutation_ack::${name}") tests;
  runCases = import ./_native-cases.nix {
    label = "native-checked-mutation-publication";
    inherit selectors;
  };
in
  sourceGate "native-checked-mutation-publication" ''
    ${runCases}
    printf 'PASS: actual checked Guard/ref publication acknowledgment (6 exact cases)\n' \
      > "$out/result"
  ''

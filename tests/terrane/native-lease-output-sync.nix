{sourceGate}: let
  selectors = [
    "gc::lease::held_tests::output_sync::acquire_and_held_renewal_sync_exact_outputs_and_all_original_controls"
    "gc::lease::held_tests::output_sync::historical_preimages_remain_checked_when_omitted_from_sync_inventory"
    "gc::lease::held_tests::output_sync::original_replacement_and_actual_expiry_refuse_before_first_sync"
    "gc::lease::held_tests::output_sync::noop_and_swallowed_real_sync_failure_never_acknowledge_renewal"
    "gc::lease::held_tests::output_sync::lease_acknowledges_real_unrelated_cache_repair_and_removal"
  ];
  runCases = import ./_native-cases.nix {
    label = "native-lease-output-sync";
    inherit selectors;
  };
in
  sourceGate "native-lease-output-sync" ''
    ${runCases}
    printf 'PASS: actual lease output durability (5 exact cases)\n' > "$out/result"
  ''

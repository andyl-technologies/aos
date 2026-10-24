{sourceGate}: let
  tests = [
    "held_renewal_reuses_actual_namespace_and_controls"
    "held_renewal_requires_exact_live_whole_lease"
    "held_renewal_acknowledges_only_actual_durable_success"
    "held_renewal_preserves_clock_continuity_and_old_expiry"
    "held_renewal_refreshes_only_acknowledged_lease_selection"
    "held_renewal_cancellation_retains_exclusion_and_poisoning"
  ];
  selectors = map (name: "gc::lease::held_tests::${name}") tests;
  runCases = import ./_native-cases.nix {
    label = "native-held-lease-renewal";
    inherit selectors;
  };
in
  sourceGate "native-held-lease-renewal" ''
    ${runCases}
    printf 'PASS: retained-context lease renewal (6 exact cases); deletion ownership remains separate\n' \
      > "$out/result"
  ''

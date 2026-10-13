{sourceGate}: let
  tests = [
    "manual_collector_clock_keeps_sleep_unsupported"
    "retained_collector_timer_advances_the_same_clock"
    "collector_timer_exposes_regression_and_dropped_sleep"
  ];
  selectors = map (name: "store::native_clock::tests::${name}") tests;
  runCases = import ./_native-cases.nix {
    label = "native-collector-clock";
    inherit selectors;
  };
in
  sourceGate "native-collector-clock" ''
    ${runCases}
    printf 'PASS: retained collector test clock (3 exact cases)\n' > "$out/result"
  ''

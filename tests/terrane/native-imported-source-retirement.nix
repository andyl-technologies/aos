{sourceGate}: let
  selector = "gc::runner::tests::source_carry::imported::local_head_foreign_used_view_survives_retirement_and_zero_node_cold_fork";
  runCases = import ./_native-cases.nix {
    label = "native-imported-source-retirement";
    selectors = [selector];
  };
in
  # The fork must use the local head with genuinely imported used-view inputs.
  sourceGate "native-imported-source-retirement" ''
    ${runCases}
    printf 'PASS: actual foreign-used-view retention and imported-head cold fork\n' > "$out/result"
  ''

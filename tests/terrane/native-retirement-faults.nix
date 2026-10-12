{sourceGate}: let
  selector = "gc::runner::tests::retirement::gc_initial_retirement_native_trash_faults_keep_exclusion_without_acknowledgment";
  runCases = import ./_native-cases.nix {
    label = "native-retirement-faults";
    selectors = [selector];
  };
in
  sourceGate "native-retirement-faults" ''
    ${runCases}
    printf 'PASS: native retirement fault matrix; permanent ownership and deletion remain separate\n' \
      > "$out/result"
  ''

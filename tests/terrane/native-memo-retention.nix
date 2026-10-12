{sourceGate}: let
  selectors = [
    "gc::runner::walk::tests::native::memos::gc_memo_native_retains_only_independently_live_output_nodes"
  ];
  runCases = import ./_native-cases.nix {
    label = "native-memo-retention";
    inherit selectors;
  };
in
  # Inspection cannot make the claimed output or recipe key a collection root.
  sourceGate "native-memo-retention" ''
    ${runCases}
    printf 'PASS: exact native conditional Memo retention prerequisite\n' > "$out/result"
  ''

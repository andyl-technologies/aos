{sourceGate}: let
  tests = [
    "memo_replay_loads_selected_records_and_complete_outputs"
    "memo_replay_keeps_disabled_and_advisory_failures_equivalent"
    "memo_replay_reports_divergence_and_rebuilds"
    "memo_replay_preserves_mandatory_input_failures_and_separate_work"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib derivation::tests::${name} -- --exact \
      > "$TMPDIR/memo-replay-test.log" 2>&1; then
      cat "$TMPDIR/memo-replay-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/memo-replay-test.log"
  '';
in
  sourceGate "memo-replay" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: read-only common Memo replay with unchanged mandatory inputs\n' > "$out/result"
  ''

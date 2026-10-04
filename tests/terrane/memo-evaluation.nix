{sourceGate}: let
  tests = [
    "memo_replays_graft_complete_recipe"
    "memo_replays_ordered_overlay_with_whiteouts"
    "memo_replays_merge_policies_and_checked_contexts"
    "memo_replays_closed_index_and_complete_carriers"
    "memo_rejects_wrong_key_and_divergent_result_until_rebuilt"
    "memo_cache_states_preserve_disabled_results"
    "memo_rebuild_returns_complete_output_closure"
    "memo_rejects_missing_inputs_and_unsupported_recipes"
    "memo_preserves_context_and_operand_configuration"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib derivation::evaluation_tests::${name} -- --exact \
      > "$TMPDIR/memo-evaluation-test.log" 2>&1; then
      cat "$TMPDIR/memo-evaluation-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/memo-evaluation-test.log"
  '';
in
  sourceGate "memo-evaluation" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: common T1 recipe replay, advisory memo behavior and complete rebuild outputs\n' > "$out/result"
  ''

{sourceGate}: let
  tests = [
    "owner_completion_binds_independent_indexes_to_new_owner"
    "owner_completion_preserves_bindings_and_unchanged_descendants"
    "owner_completion_rebuilds_divergent_binding_without_changing_index_bytes"
    "owner_completion_refuses_invalid_sources_selections_and_auxiliary_closures"
    "owner_completion_forms_common_memo_only_after_binding_and_separates_work"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::completion::tests::${name} -- --exact \
      > "$TMPDIR/index-completion-test.log" 2>&1; then
      cat "$TMPDIR/index-completion-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-completion-test.log"
  '';
in
  sourceGate "index-completion" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: immutable owner bindings precede detached index recipes and optional common Memo records\n' > "$out/result"
  ''

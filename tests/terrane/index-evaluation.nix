{sourceGate}: let
  tests = [
    "hierarchical_index_matches_independent_source_occurrences"
    "verification_rejects_divergent_rows_routes_and_gaps"
    "role_contexts_preserve_shared_nodes_without_false_authority"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::evaluation_tests::${name} -- --exact \
      > "$TMPDIR/index-evaluation-test.log" 2>&1; then
      cat "$TMPDIR/index-evaluation-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-evaluation-test.log"
  '';
in
  sourceGate "index-evaluation" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: pure canonical index construction and immutable source relationships\n' > "$out/result"
  ''

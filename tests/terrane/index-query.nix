{sourceGate}: let
  tests = [
    "candidate_ranges_match_independent_typed_rows_with_logarithmic_work"
    "occurrence_walk_preserves_local_hops_gaps_and_sharing"
    "lookup_preparation_refuses_divergent_data_and_separates_validation_work"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::lookup::tests::${name} -- --exact \
      > "$TMPDIR/index-query-test.log" 2>&1; then
      cat "$TMPDIR/index-query-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-query-test.log"
  '';
in
  sourceGate "index-query" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: immutable index candidates and local routes with measured discovery work\n' > "$out/result"
  ''

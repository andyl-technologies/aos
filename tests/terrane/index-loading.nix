{sourceGate}: let
  tests = [
    "index_loader_loads_bound_hierarchical_graph_without_mutation"
    "index_loader_preserves_physical_and_contextual_node_checks"
    "index_loader_reports_missing_bindings_and_unavailable_evidence"
    "index_loader_refuses_divergent_relationships_and_keeps_work_separate"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib indexing::tests::${name} -- --exact \
      > "$TMPDIR/index-loading-test.log" 2>&1; then
      cat "$TMPDIR/index-loading-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-loading-test.log"
  '';
in
  sourceGate "index-loading" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: retained owner-bound index loading through immutable store reads\n' > "$out/result"
  ''

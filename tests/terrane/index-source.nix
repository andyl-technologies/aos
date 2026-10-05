{sourceGate}: let
  tests = [
    "load_source_reads_unbound_namespace_without_auxiliary_reads"
    "load_source_preserves_shared_grafts_and_internal_physical_contexts"
    "load_source_keeps_typed_source_failures_and_selected_revisions"
    "load_source_drives_initialization_and_loss_rebuild_without_index_evidence"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib indexing::tests::${name} -- --exact \
      > "$TMPDIR/index-source-test.log" 2>&1; then
      cat "$TMPDIR/index-source-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-source-test.log"
  '';
in
  sourceGate "index-source" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: read-only namespace acquisition preserves mandatory initialization and rebuild inputs independently of index availability\n' > "$out/result"
  ''

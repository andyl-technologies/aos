{sourceGate}: let
  tests = [
    "node_metadata_validator_accepts_registered_node_schemas"
    "node_metadata_validator_preserves_root_and_internal_constraints"
    "node_metadata_validator_refuses_malformed_or_mixed_schemas"
    "node_metadata_validator_preserves_domain_dispatch_and_chunk_requirements"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib repository::validator::node_tests::${name} -- --exact \
      > "$TMPDIR/node-metadata-test.log" 2>&1; then
      cat "$TMPDIR/node-metadata-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/node-metadata-test.log"
  '';
in
  sourceGate "node-metadata" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: registered Node schemas through the existing metadata validator\n' > "$out/result"
  ''

{sourceGate}: let
  tests = [
    "memo_metadata_validator_accepts_exact_common_schema"
    "memo_metadata_validator_refuses_malformed_schema_and_recipe_bytes"
    "memo_metadata_validator_preserves_existing_domain_dispatch"
    "memo_metadata_validator_has_no_chunk_requirements"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib repository::validator::memo_tests::${name} -- --exact \
      > "$TMPDIR/memo-metadata-test.log" 2>&1; then
      cat "$TMPDIR/memo-metadata-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/memo-metadata-test.log"
  '';
in
  sourceGate "memo-metadata" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: common Memo schema dispatch through the existing metadata validator\n' > "$out/result"
  ''

{sourceGate}: let
  tests = [
    "memo_record_matches_independent_wire_and_identity"
    "memo_record_refuses_every_truncation_and_noncanonical_schema"
    "memo_identity_separates_recipe_lookup_and_record_fields"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib derivation::record_tests::${name} -- --exact \
      > "$TMPDIR/memo-format-test.log" 2>&1; then
      cat "$TMPDIR/memo-format-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/memo-format-test.log"
  '';
in
  sourceGate "memo-format" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: canonical common memo records and distinct recipe lookup keys\n' > "$out/result"
  ''

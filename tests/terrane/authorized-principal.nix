{sourceGate}: let
  tests = [
    "authenticated_principal_comparison_requires_name_and_kind"
    "authenticated_principal_comparison_keeps_request_claims_independent"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --lib guard::principal_tests::${name} -- --exact \
      > "$TMPDIR/authorized-principal-test.log" 2>&1; then
      cat "$TMPDIR/authorized-principal-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/authorized-principal-test.log"
  '';
in
  sourceGate "authorized-principal" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: authenticated principal name/kind and independent claims\n' > "$out/result"
  ''

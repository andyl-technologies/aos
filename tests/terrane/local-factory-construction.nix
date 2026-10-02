{sourceGate}: let
  tests = [
    "local_bootstrap_private_tree_passes_actual_guard_admission"
    "local_directory_edit_preserves_canonical_implicit_owner_on_reopen"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane --no-default-features --features tokio,surface-sdk --lib \
      repository::local::tests::${name} -- --exact \
      > "$TMPDIR/local-factory-test.log" 2>&1; then
      cat "$TMPDIR/local-factory-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/local-factory-test.log"
  '';
in
  sourceGate "local-factory-construction" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: ordinary local construction and strict reopen regression paths\n' > "$out/result"
  ''

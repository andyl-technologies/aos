{sourceGate}: let
  tests = [
    "owner_bindings_require_canonical_noninherited_root_values"
    "executable_index_recipes_are_closed_and_legacy_recipes_remain_data"
    "index_keys_roundtrip_exact_canonical_values_and_object_targets"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::tests::${name} -- --exact \
      > "$TMPDIR/index-format-test.log" 2>&1; then
      cat "$TMPDIR/index-format-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-format-test.log"
  '';
in
  sourceGate "index-format" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: exact owner bindings, closed executable index recipes and opaque key formats\n' > "$out/result"
  ''

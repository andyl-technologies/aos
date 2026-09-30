{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';
in {
  canonical-cbor = sourceGate "canonical-cbor" ''
    cd crates
    ${runTests "cbor::tests"}
    ${runTests "gc::lease::tests"}
    ${runTests "tree_format::tests::golden_leaf_round_trips_byte_exactly -- --exact"}
    printf 'PASS: canonical CBOR and golden leaf encoding\n' > "$out/result"
  '';

  tree-well-formed = sourceGate "tree-well-formed" ''
    cd crates
    ${runTests "tree_format::tests"}
    printf 'PASS: tree node and entry validation\n' > "$out/result"
  '';
}

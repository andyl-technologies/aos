{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';
in {
  property-resolution = sourceGate "property-resolution" ''
    cd crates
    ${runTests "properties::tests::resolution"}
    printf 'PASS: closed registry and view-path property resolution\n' > "$out/result"
  '';

  property-required-attrs = sourceGate "property-required-attrs" ''
    cd crates
    ${runTests "properties::tests::required_attrs"}
    printf 'PASS: changed-entry attribute requirements and completeness\n' > "$out/result"
  '';

  property-domain-reference = sourceGate "property-domain-reference" ''
    cd crates
    ${runTests "properties::tests::domain_reference"}
    printf 'PASS: disclosure references and boundary transitions\n' > "$out/result"
  '';
}

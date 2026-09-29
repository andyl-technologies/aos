{sourceGate, ...}: {
  ref-names = sourceGate "ref-names" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib refs:: > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output) is None)' "$TMPDIR/test.log"
    printf 'PASS: ref names, records, ancestry, and merge bases\n' > "$out/result"
  '';
}

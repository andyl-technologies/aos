{sourceGate, ...}: {
  ref-names = sourceGate "ref-names" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib refs::
    printf 'PASS: ref names, records, ancestry, and merge bases\n' > "$out/result"
  '';
}

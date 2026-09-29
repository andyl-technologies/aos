{sourceGate, ...}: {
  ref-names = sourceGate "ref-names" ''
    cd crates
    cargo nextest run --frozen --offline -p terrane-core
    printf 'PASS: ref names, records, ancestry, and merge bases\n' > "$out/result"
  '';
}

{sourceGate, ...}: {
  canonical-cbor = sourceGate "canonical-cbor" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib cbor::tests
    cargo test --frozen --offline -p terrane-core --lib tree_format::tests::golden_leaf_round_trips_byte_exactly
    printf 'PASS: canonical CBOR and golden leaf encoding\n' > "$out/result"
  '';

  tree-well-formed = sourceGate "tree-well-formed" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib tree_format::tests
    printf 'PASS: tree node and entry validation\n' > "$out/result"
  '';
}

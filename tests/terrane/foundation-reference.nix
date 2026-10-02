{sourceGate}:
sourceGate "foundation-reference-generator" ''
  cd crates
  cargo build --frozen --offline -p terrane-core --example reference_blake3
  reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
  python3 ../tests/terrane/foundation_vectors.py --self-check \
    --blake3-bin "$reference_binary" > "$out/result"
  python3 ../tests/terrane/foundation_vectors.py --emit \
    --blake3-bin "$reference_binary" > "$out/reference.md"
  cp "$reference_binary" "$out/reference_blake3"
''

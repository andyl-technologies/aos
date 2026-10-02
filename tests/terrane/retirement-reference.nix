{sourceGate}:
sourceGate "retirement-reference-generator" ''
  cd crates
  cargo build --frozen --offline -p terrane-core --example reference_blake3
  reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
  python3 ../tests/terrane/retirement_vectors.py --self-check \
    --blake3-bin "$reference_binary" > "$out/result"
  python3 ../tests/terrane/retirement_vectors.py --emit \
    --blake3-bin "$reference_binary" > "$out/reference.md"
  python3 ../tests/terrane/retirement_vectors.py --check "$out/reference.md" \
    --blake3-bin "$reference_binary" >> "$out/result"
''

# Qualifies the pure structural codec, independently of FUSE mount conformance.
{sourceGate}:
sourceGate "structural-index" ''
  cd crates
  cargo test --frozen --offline -p terrane-linux --no-default-features \
    --features surface-fuse --lib --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/structural_index_proof.py
  printf '%s\n' PASS > "$out/result"
''

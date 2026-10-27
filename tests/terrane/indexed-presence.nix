# Checks committed index-only membership without replacing verified body reads.
{sourceGate}:
sourceGate "indexed-presence" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test indexed_presence --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/indexed_presence_proof.py
  printf '%s\n' PASS > "$out/result"
''

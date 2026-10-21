# Qualifies report compatibility; composite backend opening remains separate.
{sourceGate}:
sourceGate "store-expression-opened" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test store_expression --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/store_expression_proof.py
  printf '%s\n' PASS > "$out/result"
''

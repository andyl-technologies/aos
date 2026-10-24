# Qualifies exact private fallback reads through generated-client socket calls.
{sourceGate}:
sourceGate "range-client" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test range_client --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/range_client_proof.py
  printf '%s\n' PASS > "$out/result"
''

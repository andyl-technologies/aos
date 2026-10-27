# Qualifies private RPC completion using actual generated-client socket reads.
{sourceGate}:
sourceGate "bundle-client" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test bundle_client --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/bundle_client_proof.py
  printf '%s\n' PASS > "$out/result"
''

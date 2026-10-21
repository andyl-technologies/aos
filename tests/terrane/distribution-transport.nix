# Qualifies native binding only; service policy and backend conformance are separate.
{sourceGate}:
sourceGate "distribution-transport" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test distribution_transport --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/distribution_transport_proof.py
  printf '%s\n' PASS > "$out/result"
''

# Qualifies native static-key issuance; request authentication and GCP exchange are separate.
{sourceGate}:
sourceGate "workload-issuer" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test workload_issuer --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/workload_issuer_proof.py
  printf '%s\n' PASS > "$out/result"
''

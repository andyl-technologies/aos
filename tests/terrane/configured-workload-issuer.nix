# Opens actual configured file authority; no remote authentication endpoint claim.
{sourceGate}:
sourceGate "configured-workload-issuer" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test configured_workload_issuer --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/configured_workload_issuer_proof.py
  printf '%s\n' PASS > "$out/result"
''

# Qualifies actual JWT verification and job assignment using recorded instance fixtures.
{sourceGate}:
sourceGate "gcp-instance-issuer" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test gcp_instance_issuer --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/gcp_instance_proof.py
  printf '%s\n' PASS > "$out/result"
''

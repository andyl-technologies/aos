# Qualifies local guarded Ref reads; CAS, watch, remote freshness and deployment remain open.
{sourceGateWithInputs}:
sourceGateWithInputs {preserveArtifactBytes = true;} "local-ref-service" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test local_ref_service --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/local_ref_service_proof.py
  printf '%s\n' PASS > "$out/result"
''

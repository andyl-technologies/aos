# Qualifies private bounded bundle reception without claiming backend admission.
{sourceGate}:
sourceGate "bundle-receive" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test bundle_receive --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/bundle_receive_proof.py
  printf '%s\n' PASS > "$out/result"
''

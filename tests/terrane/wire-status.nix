# Qualifies actual native structured status serialization, without service policy claims.
{sourceGate}:
sourceGate "wire-status" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test wire_contract --no-run --message-format=json > "$out/build.jsonl"
  TERRANE_WIRE_NATIVE=1 python3 ../tests/terrane/wire_contract_proof.py
  printf '%s\n' PASS > "$out/result"
''

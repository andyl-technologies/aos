# Qualifies generated codecs, separately from implemented Distribution services.
{sourceGate}:
sourceGate "wire-contract" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --no-default-features \
    --test wire_contract --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/wire_contract_proof.py
  printf '%s\n' PASS > "$out/result"
''

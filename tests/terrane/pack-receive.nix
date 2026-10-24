# Qualifies private receive verification; backend admission and publication are separate.
{sourceGate}:
sourceGate "pack-receive" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --no-default-features \
    --test pack_receive --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/pack_receive_proof.py
  printf '%s\n' PASS > "$out/result"
''

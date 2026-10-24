# Qualifies SDK history and its selection invariants, not a deployed RPC service.
{sourceGate}:
sourceGate "ref-history" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test ref_history --no-run --message-format=json > "$out/build.jsonl"
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --lib --no-run --message-format=json > "$out/unit-build.jsonl"
  python3 ../tests/terrane/ref_history_proof.py
  printf '%s\n' PASS > "$out/result"
''

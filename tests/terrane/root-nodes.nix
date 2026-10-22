# Qualifies complete guarded metadata disclosure without requesting file bodies.
{sourceGate}:
sourceGate "root-nodes" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test root_nodes --no-run --message-format=json > "$out/build.jsonl"
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --lib --no-run --message-format=json > "$out/unit-build.jsonl"
  python3 ../tests/terrane/root_nodes_proof.py
  printf '%s\n' PASS > "$out/result"
''

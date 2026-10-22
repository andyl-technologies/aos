# Qualifies current guarded point reads without claiming deployed GetRef.
{sourceGate}:
sourceGate "ref-head" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test ref_head --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/ref_head_proof.py
  printf '%s\n' PASS > "$out/result"
''

# Qualifies guarded complete SDK enumeration, not deployed ListRefs or WatchRefs.
{sourceGate}:
sourceGate "ref-listing" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test ref_listing --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/ref_listing_proof.py
  printf '%s\n' PASS > "$out/result"
''

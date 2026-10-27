# Qualifies byte streaming only; Distribution service conformance is separate.
{sourceGate}:
sourceGate "streaming-http" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --features tokio \
    --test streaming_http --no-run --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/streaming_http_proof.py
  printf '%s\n' PASS > "$out/result"
''

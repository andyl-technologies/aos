{sourceGate}:
# This output shares compilation, never qualification results. Every consuming
# gate discovers and executes its own exact cases in a fresh protected namespace
# (CRATE-22 through CRATE-27, ALG-32).
sourceGate "native-sdk-test-image" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --no-default-features \
    --features tokio,surface-sdk --lib --no-run --message-format=json \
    > "$TMPDIR/native-sdk-build.jsonl"
  cargo metadata --frozen --offline --no-deps --format-version=1 \
    > "$TMPDIR/native-sdk-packages.json"
  rustc --print sysroot > "$TMPDIR/native-sdk-sysroot.txt"
  rustc --print target-libdir > "$TMPDIR/native-sdk-target-libdir.txt"

  python3 ${./native_sdk_test_image.py}
''

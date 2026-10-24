{sourceGate}:
# This image shares immutable compilation inputs and binaries, never results.
# Consumers discover and execute their own cases in fresh protected storage.
sourceGate "surface-test-image" ''
  cd crates
  cargo test --frozen --offline -p terrane-sdk --no-default-features \
    --features tokio,surface-sdk --test local_sdk --test surface_contract \
    --test surface_runtime --test surface_lifecycle_contract \
    --test configured_local_repository \
    --no-run --message-format=json > "$TMPDIR/surface-build.jsonl"
  cargo metadata --frozen --offline --no-deps --format-version=1 \
    > "$TMPDIR/surface-packages.json"
  rustc --print target-libdir > "$TMPDIR/surface-target-libdir.txt"

  python3 ${./surface_test_image.py} ${./native_sdk_test_image.py}
''

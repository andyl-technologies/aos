{sourceGate}: let
  selectors = [
    "gc::runner::walk::tests::native::memos::gc_memo_native_retains_only_independently_live_output_nodes"
  ];
in
  # Inspection cannot make the claimed output or recipe key a collection root.
  sourceGate "native-memo-retention" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/memo-retention-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/memo-retention-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/memo-retention-test.log" 2>&1; then
        cat "$TMPDIR/memo-retention-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/memo-retention-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: exact native conditional Memo retention prerequisite\n' > "$out/result"
  ''

{sourceGate}: let
  selector = "ref_advance::disclosure_tests::disclosure_boundary_nested_and_repeated_root_occurrences_check_actual_domains";
  required = builtins.toJSON [selector];
in
  sourceGate "disclosure-denied-diagnostic" ''
    cd crates
    cargo test --frozen --offline -p terrane --lib --no-default-features --features std,send,tokio \
      ${selector} -- --exact --list > "$TMPDIR/inventory.log"
    python3 ../tests/terrane/check_native_gate.py inventory "$TMPDIR/inventory.log" '${required}'

    # Only this local diagnostic enables failure-site reporting. Its output
    # preserves a selected denial without changing the ordinary conformance gates.
    if TERRANE_TEST_DENIAL_CALLSITE=1 cargo test --frozen --offline -p terrane --lib \
      --no-default-features --features std,send,tokio ${selector} \
      -- --exact --nocapture --test-threads=1 > "$TMPDIR/native.log" 2>&1; then
      python3 ../tests/terrane/check_native_gate.py execution "$TMPDIR/native.log" '${required}'
    else
      native_test_status=$?
      cat "$TMPDIR/native.log" >&2
      exit "$native_test_status"
    fi

    printf 'PASS: one local disclosure diagnostic; conformance gates remain independent\n' > "$out/result"
  ''

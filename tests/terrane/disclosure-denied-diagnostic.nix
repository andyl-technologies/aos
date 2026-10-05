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
      cat "$TMPDIR/native.log"
      # Nocapture diagnostics can interrupt libtest's named status line. Exact
      # discovery and the identical exact filter bind this one-case summary.
      python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); sys.exit(0 if re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output) else "exact diagnostic did not execute one passing, non-ignored case")' \
        "$TMPDIR/native.log"
    else
      native_test_status=$?
      cat "$TMPDIR/native.log" >&2
      exit "$native_test_status"
    fi

    printf 'PASS: one local disclosure diagnostic; conformance gates remain independent\n' > "$out/result"
  ''

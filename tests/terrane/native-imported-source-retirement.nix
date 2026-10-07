{sourceGate}: let
  selector = "gc::runner::tests::source_carry::imported::local_head_foreign_used_view_survives_retirement_and_zero_node_cold_fork";
in
  # The fork must use the local head with genuinely imported used-view inputs.
  sourceGate "native-imported-source-retirement" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/imported-source-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/imported-source-tests.txt" '${builtins.toJSON [selector]}'

    if ! cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib '${selector}' -- --exact \
      > "$TMPDIR/imported-source-test.log" 2>&1; then
      cat "$TMPDIR/imported-source-test.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$TMPDIR/imported-source-test.log" '${builtins.toJSON [selector]}'
    printf 'PASS: actual foreign-used-view retention and imported-head cold fork\n' > "$out/result"
  ''

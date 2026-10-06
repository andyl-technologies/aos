{sourceGate}: let
  selector = "gc::runner::tests::retirement::gc_initial_retirement_native_trash_faults_keep_exclusion_without_acknowledgment";
in
  sourceGate "native-retirement-faults" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/retirement-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/retirement-tests.txt" '${builtins.toJSON [selector]}'
    if ! cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib '${selector}' -- --exact \
      > "$TMPDIR/retirement-test.log" 2>&1; then
      cat "$TMPDIR/retirement-test.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$TMPDIR/retirement-test.log" '${builtins.toJSON [selector]}'
    printf 'PASS: native retirement fault matrix; permanent ownership and deletion remain separate\n' \
      > "$out/result"
  ''

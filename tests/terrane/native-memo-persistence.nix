{sourceGate}: let
  names = [
    "common_memo_persists_and_reopens_all_t1_outputs"
    "common_memo_optional_loss_preserves_disabled_results"
    "common_memo_divergence_refuses_until_complete_persisted_rebuild"
    "common_memo_replay_preserves_actual_current_original_and_trust_checks"
  ];
  selectors = map (name: "derivation::tests::native::${name}") names;
in
  # This leaf reuses the common replay and does not certify root-associated GC.
  sourceGate "native-memo-persistence" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/memo-persistence-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/memo-persistence-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/memo-persistence-test.log" 2>&1; then
        cat "$TMPDIR/memo-persistence-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/memo-persistence-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: four exact native common Memo persistence prerequisites\n' > "$out/result"
  ''

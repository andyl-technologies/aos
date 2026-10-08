{sourceGate}: let
  names = [
    "unrelated_public_trust_install_carries_selected_source_without_node_io"
    "unrelated_public_branch_advance_preserves_separate_zero_node_fork"
    "successive_public_trust_installs_recheck_foreign_original_dependencies"
    "final_guard_install_refuses_original_lost_after_carry_qualification"
  ];
  selectors = map (name: "selected_bridge::native_guard::cold_fork::tests::ordinary::publication::guard_carry::${name}") names;
in
  # The measured carry interval ends only after the real Guard publication ACK.
  sourceGate "native-guard-carry" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/guard-carry-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/guard-carry-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/guard-carry-test.log" 2>&1; then
        cat "$TMPDIR/guard-carry-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/guard-carry-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: four exact native held Guard source-preservation cases\n' > "$out/result"
  ''

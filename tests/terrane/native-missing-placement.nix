{sourceGate}: let
  names = [
    "missing_pack_reoffering_selects_fresh_verified_placement"
    "missing_index_reoffering_selects_fresh_verified_placement"
    "present_corruption_never_becomes_missing_placement"
    "quarantine_and_exclusion_never_become_missing_placement"
    "unavailable_artifact_read_never_becomes_missing_placement"
    "original_absence_and_ancestry_survive_native_publication_handoff"
    "raw_publication_ack_requires_actual_complete_durability"
  ];
  selectors = map (name: "bucket::missing_placement::tests::${name}") names;
in
  # Creator records and Raw acknowledgment must come from actual native execution.
  sourceGate "native-missing-placement" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/missing-placement-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/missing-placement-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/missing-placement-test.log" 2>&1; then
        cat "$TMPDIR/missing-placement-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/missing-placement-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: seven exact native missing-placement and Raw durability cases\n' > "$out/result"
  ''

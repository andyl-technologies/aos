{sourceGate}: let
  selectors = [
    "gc::lease::held_tests::output_sync::acquire_and_held_renewal_sync_exact_outputs_and_all_original_controls"
    "gc::lease::held_tests::output_sync::historical_preimages_remain_checked_when_omitted_from_sync_inventory"
    "gc::lease::held_tests::output_sync::original_replacement_and_actual_expiry_refuse_before_first_sync"
    "gc::lease::held_tests::output_sync::noop_and_swallowed_real_sync_failure_never_acknowledge_renewal"
    "gc::lease::held_tests::output_sync::lease_acknowledges_real_unrelated_cache_repair_and_removal"
  ];
in
  sourceGate "native-lease-output-sync" ''
    cd crates
    if ! cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$out/inventory.log" 2>&1; then
      cat "$out/inventory.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/inventory.log" '${builtins.toJSON selectors}'
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      test_log="$out/$test_name.log"
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$test_log" 2>&1; then
        cat "$test_log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$test_log" "[\"$test_name\"]"
    done
    printf 'PASS: actual lease output durability (5 exact cases)\n' > "$out/result"
  ''

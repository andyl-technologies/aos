{sourceGate}: let
  tests = [
    "pinned::sdk_checkout_public_api_pins_ref_and_fixed_commit_across_reopen"
    "pinned::sdk_checkout_public_api_confines_subtree_and_preserves_supported_entries"
    "refusals::sdk_checkout_public_api_rejects_unavailable_registry_mode_endpoint_and_policy"
    "refusals::sdk_checkout_public_api_refuses_current_acl_and_missing_original_authority"
    "lifecycle::sdk_checkout_public_api_lifecycle_preserves_completed_directory"
  ];
in
  sourceGate "local-sdk-checkout" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --test local_sdk -- --list > "$TMPDIR/sdk-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/sdk-tests.txt" '${builtins.toJSON tests}'
    for test_name in ${builtins.concatStringsSep " " tests}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --test local_sdk "$test_name" -- --exact \
        > "$TMPDIR/sdk-test.log" 2>&1; then
        cat "$TMPDIR/sdk-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/sdk-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: supported public local SDK checkout (5 exact cases); broader SDK conformance remains separate\n' \
      > "$out/result"
  ''

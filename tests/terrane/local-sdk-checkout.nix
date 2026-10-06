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
    python3 - "$TMPDIR/sdk-tests.txt" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    required = ${builtins.toJSON tests}
    if len(required) != len(set(required)):
        raise SystemExit("duplicate required local SDK test")

    missing = [name for name in required if f"{name}: test" not in names]
    if missing:
        raise SystemExit(f"required public local SDK tests are missing: {missing}")
    PYTEST
    for test_name in ${builtins.concatStringsSep " " tests}; do
      cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --test local_sdk "$test_name" -- --exact
    done
    printf 'PASS: supported public local SDK checkout (5 exact cases); broader SDK conformance remains separate\n' \
      > "$out/result"
  ''

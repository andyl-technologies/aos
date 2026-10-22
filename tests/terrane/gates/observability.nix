{sourceGate, ...}: {
  obs-blame = sourceGate "obs-blame" ''
    cd crates
    cargo test --frozen --offline -p terrane-sdk --features tokio,surface-sdk \
      --test entry_blame --no-run --message-format=json > "$out/sdk-build.jsonl"
    cargo test --frozen --offline -p terrane-sdk --features tokio,surface-sdk \
      --test entry_blame -- --list > "$out/sdk-inventory.log"
    sdk_tests='["blame_requires_only_selected_root_read_and_refuses_other_scopes","blame_uses_signed_metadata_without_requesting_object_bodies"]'
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/sdk-inventory.log" "$sdk_tests"
    for test_name in \
      blame_requires_only_selected_root_read_and_refuses_other_scopes \
      blame_uses_signed_metadata_without_requesting_object_bodies; do
      if ! cargo test --frozen --offline -p terrane-sdk --features tokio,surface-sdk \
        --test entry_blame "$test_name" -- --exact > "$out/$test_name.log" 2>&1; then
        cat "$out/$test_name.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$out/$test_name.log" "[\"$test_name\"]"
    done

    cargo test --frozen --offline -p terrane-cli --test local_cli \
      --no-run --message-format=json > "$out/cli-build.jsonl"
    test_name=local_blame_preserves_introduction_through_merges_and_refuses_unauthorized_output
    if ! cargo test --frozen --offline -p terrane-cli --test local_cli \
      "$test_name" -- --exact > "$out/$test_name.log" 2>&1; then
      cat "$out/$test_name.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/$test_name.log" "[\"$test_name\"]"
    printf 'PASS: signed graph blame, scoped SDK reads, no object bodies and CLI merge audit\n' \
      > "$out/result"
  '';
}

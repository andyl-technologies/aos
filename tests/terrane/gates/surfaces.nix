{sourceGate}: let
  runTests = target: cases: ''
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --test ${target} -- --list > "$TMPDIR/${target}-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/${target}-tests.txt" '${builtins.toJSON cases}'
    for test_name in ${builtins.concatStringsSep " " cases}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --test ${target} "$test_name" -- --exact \
        > "$TMPDIR/${target}-test.log" 2>&1; then
        cat "$TMPDIR/${target}-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/${target}-test.log" "[\"$test_name\"]"
    done
  '';
in {
  surface-interface = sourceGate "surface-interface" ''
    cd crates
    ${runTests "surface_contract" ["shared_role_configuration_requires_explicit_invocation_selection" "registry_cannot_claim_uncompiled_or_runtime_loaded_surfaces" "exposures_preserve_order_and_reject_partial_configuration" "token_references_reject_inline_credentials_and_invalid_locators"]}
    ${runTests "surface_runtime" ["preparation_refuses_entire_list_before_any_endpoint_starts" "prepared_snapshots_recheck_current_authority_before_startup"]}
    ${runTests "surface_lifecycle_contract" ["external_surface_owns_real_lifecycle_without_sdk_constructor_or_registration"]}
    printf 'PASS: compiled registry, exposure contract and atomic preparation\n' > "$out/result"
  '';
  surface-commit-path = sourceGate "surface-commit-path" ''
    cd crates
    ${runTests "surface_runtime" ["readonly_sdk_refuses_writer_mode_before_any_endpoint_or_mutation"]}
    printf 'PASS: T2 read-only SDK refuses every configured write path; writable surfaces remain unavailable\n' > "$out/result"
  '';
  surface-schema = sourceGate "surface-schema" ''
    cd crates
    ${runTests "surface_contract" ["metadata_schema_checks_root_types_properties_and_forbidden_paths" "schemas_check_entry_kinds_attributes_root_and_forbidden_matches" "schema_collections_allow_empty_matches_but_literal_entries_establish_existence" "malformed_schema_patterns_fail_independently_of_tree_matches"]}
    ${runTests "surface_runtime" ["schema_refusal_precedes_sdk_directory_creation"]}
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib \
      repository::read::schema_tests::schema_metadata_reads_never_fetch_plaintext_chunks \
      -- --exact > "$TMPDIR/schema-metadata.log" 2>&1 || {
        cat "$TMPDIR/schema-metadata.log"
        exit 1
      }
    python3 ../tests/terrane/check_native_gate.py execution \
      "$TMPDIR/schema-metadata.log" '["repository::read::schema_tests::schema_metadata_reads_never_fetch_plaintext_chunks"]'
    printf 'PASS: metadata schemas refuse invalid SDK roots before presentation\n' > "$out/result"
  '';
  surface-status = sourceGate "surface-status" ''
    cd crates
    ${runTests "surface_runtime" ["prepared_snapshots_keep_validated_commit_and_report_complete_status" "sdk_presents_attribute_ownership_canonical_times_and_filtered_xattrs"]}
    ${runTests "local_sdk" ["lifecycle::sdk_checkout_public_api_lifecycle_preserves_completed_directory"]}
    printf 'PASS: pinned SDK identity, status and monotonic lifecycle\n' > "$out/result"
  '';
}

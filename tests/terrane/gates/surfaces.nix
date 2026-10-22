{
  pkgs,
  lib,
  sourceGateWithInputs,
  nativeSdkGate,
  ...
}: let
  testImage = import ../surface-test-image.nix {
    sourceGate = sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  withImage = builder: name: script:
    builder name ''
      cd crates
      python3 ${../surface_test_image.py} ${../native_sdk_test_image.py} \
        --verify ${testImage}
      export TERRANE_SURFACE_TEST_IMAGE=${testImage}
      ${script}
    '';
  surfaceGate = withImage (sourceGateWithInputs {});
  surfaceSchemaGate = withImage nativeSdkGate;
  presentationVm = import ../surface-presentation-ext4.nix {
    inherit pkgs lib testImage;
  };
  runTests = target: cases: ''
    surface_binary="$TERRANE_SURFACE_TEST_IMAGE/targets/${target}/bin/terrane-native-sdk-tests"
    "$surface_binary" --list > "$TMPDIR/${target}-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/${target}-tests.txt" '${builtins.toJSON cases}'
    for test_name in ${builtins.concatStringsSep " " cases}; do
      if ! "$surface_binary" "$test_name" --exact \
        > "$TMPDIR/${target}-test.log" 2>&1; then
        cat "$TMPDIR/${target}-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/${target}-test.log" "[\"$test_name\"]"
    done
  '';
in {
  surface-interface = surfaceGate "surface-interface" ''
    ${runTests "surface_contract" ["native_host_configuration_preserves_explicit_runtime_inputs" "native_host_configuration_rejects_missing_or_ambiguous_operator_inputs" "shared_host_configuration_preserves_requested_policy_without_runtime_claims" "shared_role_configuration_requires_explicit_invocation_selection" "registry_cannot_claim_uncompiled_or_runtime_loaded_surfaces" "exposures_preserve_order_and_reject_partial_configuration" "token_references_reject_inline_credentials_and_invalid_locators"]}
    ${runTests "surface_runtime" ["preparation_refuses_entire_list_before_any_endpoint_starts" "prepared_snapshots_recheck_current_authority_before_startup"]}
    ${runTests "surface_lifecycle_contract" ["external_surface_owns_real_lifecycle_without_sdk_constructor_or_registration"]}
    ${runTests "configured_local_repository" ["configured_local_reopen_prepares_and_starts_actual_read_only_sdk" "configured_local_reopen_never_substitutes_instance_token_for_exposure" "configured_local_reopen_rejects_unsupported_stores_and_nonserve_roles" "configured_local_reopen_requires_original_trust_and_validated_timing" "configured_local_reopen_preserves_signed_current_acl_denial" "configured_read_cache_preserves_original_authority_and_refuses_writes" "configured_complete_content_driver_preserves_authority_and_is_not_bypassed"]}
    printf 'PASS: compiled registry, exposure contract and atomic preparation\n' > "$out/result"
  '';
  surface-commit-path = surfaceGate "surface-commit-path" ''
    ${runTests "surface_runtime" ["readonly_sdk_refuses_writer_mode_before_any_endpoint_or_mutation"]}
    printf 'PASS: T2 read-only SDK refuses every configured write path; writable surfaces remain unavailable\n' > "$out/result"
  '';
  surface-schema = surfaceSchemaGate "surface-schema" ''
    ${runTests "surface_contract" ["metadata_schema_checks_root_types_properties_and_forbidden_paths" "schemas_check_entry_kinds_attributes_root_and_forbidden_matches" "schema_collections_allow_empty_matches_but_literal_entries_establish_existence" "malformed_schema_patterns_fail_independently_of_tree_matches"]}
    ${runTests "surface_runtime" ["schema_refusal_precedes_sdk_directory_creation"]}
    observer=repository::read::schema_tests::schema_metadata_reads_never_fetch_plaintext_chunks
    "$TERRANE_NATIVE_SDK_TEST_BINARY" --list > "$TMPDIR/schema-metadata-inventory.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/schema-metadata-inventory.txt" "[\"$observer\"]"
    "$TERRANE_NATIVE_SDK_TEST_BINARY" "$observer" --exact \
      > "$TMPDIR/schema-metadata.log" 2>&1 || {
        cat "$TMPDIR/schema-metadata.log"
        exit 1
      }
    python3 ../tests/terrane/check_native_gate.py execution \
      "$TMPDIR/schema-metadata.log" "[\"$observer\"]"
    printf 'PASS: metadata schemas refuse invalid SDK roots before presentation\n' > "$out/result"
  '';
  surface-status = surfaceGate "surface-status" ''
    ${runTests "surface_runtime" ["prepared_snapshots_keep_validated_commit_and_report_complete_status"]}
    ${runTests "local_sdk" ["lifecycle::sdk_checkout_public_api_lifecycle_preserves_completed_directory"]}
    test "$(cat ${presentationVm}/result)" = PASS
    printf 'PASS: pinned SDK identity, status and monotonic lifecycle\n' > "$out/result"
  '';
}

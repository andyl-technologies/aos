# Requires actual common Memo replay and metadata storage witnesses.
{sourceGate, ...}: let
  coreTests = [
    "derivation::record_tests::memo_record_matches_independent_wire_and_identity"
    "derivation::record_tests::memo_record_refuses_every_truncation_and_noncanonical_schema"
    "derivation::record_tests::memo_identity_separates_recipe_lookup_and_record_fields"
    "derivation::evaluation_tests::memo_replays_graft_complete_recipe"
    "derivation::evaluation_tests::memo_replays_ordered_overlay_with_whiteouts"
    "derivation::evaluation_tests::memo_replays_merge_policies_and_checked_contexts"
    "derivation::evaluation_tests::memo_replays_closed_index_and_complete_carriers"
    "derivation::evaluation_tests::memo_rejects_wrong_key_and_divergent_result_until_rebuilt"
    "derivation::evaluation_tests::memo_cache_states_preserve_disabled_results"
    "derivation::evaluation_tests::memo_rebuild_returns_complete_output_closure"
    "derivation::evaluation_tests::memo_rejects_missing_inputs_and_unsupported_recipes"
    "derivation::evaluation_tests::memo_preserves_context_and_operand_configuration"
    "derivation::evaluation_tests::overlay::complete_nested_overlay_uses_same_evaluator_for_disabled_miss_hit_and_rebuild"
    "derivation::evaluation_tests::overlay::cached_nested_overlay_cannot_bypass_missing_roots_or_independent_policy"
    "derivation::evaluation_tests::overlay::every_cache_mode_rechecks_projected_policy_independently_of_source_policy"
    "derivation::evaluation_tests::overlay::shared_overlay_target_retains_distinct_original_occurrence_policies"
    "derivation::evaluation_tests::overlay::nested_overlay_rebinds_recorded_domains_without_using_them_as_policy_context"
  ];

  nativeTests = [
    "repository::validator::memo_tests::memo_metadata_validator_accepts_exact_common_schema"
    "repository::validator::memo_tests::memo_metadata_validator_refuses_malformed_schema_and_recipe_bytes"
    "repository::validator::memo_tests::memo_metadata_validator_preserves_existing_domain_dispatch"
    "repository::validator::memo_tests::memo_metadata_validator_has_no_chunk_requirements"
    "derivation::tests::memo_replay_loads_selected_records_and_complete_outputs"
    "derivation::tests::memo_replay_keeps_disabled_and_advisory_failures_equivalent"
    "derivation::tests::memo_replay_reports_divergence_and_rebuilds"
    "derivation::tests::memo_replay_preserves_mandatory_input_failures_and_separate_work"
    "pack::metadata_tests::metadata_kinds_roundtrip_pack_detached_index_and_merged_shard"
    "pack::metadata_tests::metadata_kinds_reject_wrong_domains_and_data_class"
    "pack::metadata_tests::metadata_bundle_verifies_all_three_domains_before_exposure"
  ];

  retainedTests = [
    "derivation::tests::native::common_memo_persists_and_reopens_all_t1_outputs"
    "derivation::tests::native::common_memo_optional_loss_preserves_disabled_results"
    "derivation::tests::native::common_memo_divergence_refuses_until_complete_persisted_rebuild"
    "derivation::tests::native::common_memo_replay_preserves_actual_current_original_and_trust_checks"
    "derivation::tests::native::overlay::native_nested_overlay_reopens_closure_and_rechecks_policy"
    "gc::runner::walk::tests::native::memos::gc_memo_native_retains_only_independently_live_output_nodes"
  ];

  runRetainedTest = name: ''
    if ! cargo test --frozen --offline -p terrane-sdk --no-default-features \
      --features tokio,surface-sdk --lib ${name} -- --exact \
      > "$out/retained-${name}.log" 2>&1; then
      cat "$out/retained-${name}.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/retained-${name}.log" '${builtins.toJSON [name]}'
  '';

  runTest = package: name: ''
    if ! cargo test --frozen --offline -p ${package} --lib ${name} -- --exact \
      > "$out/${package}-${name}.log" 2>&1; then
      cat "$out/${package}-${name}.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/${package}-${name}.log" '${builtins.toJSON [name]}'
  '';
in {
  derivation-memo = sourceGate "derivation-memo" ''
    cd crates
    if ! cargo test --frozen --offline -p terrane-format --lib -- --list \
      > "$out/core-inventory.log" 2>&1; then
      cat "$out/core-inventory.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/core-inventory.log" '${builtins.toJSON coreTests}'

    if ! cargo test --frozen --offline -p terrane-sdk --lib -- --list \
      > "$out/native-inventory.log" 2>&1; then
      cat "$out/native-inventory.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/native-inventory.log" '${builtins.toJSON nativeTests}'

    if ! cargo test --frozen --offline -p terrane-sdk --no-default-features \
      --features tokio,surface-sdk --lib -- --list \
      > "$out/retained-inventory.log" 2>&1; then
      cat "$out/retained-inventory.log"
      exit 1
    fi
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/retained-inventory.log" '${builtins.toJSON retainedTests}'

    ${builtins.concatStringsSep "\n" (map (runTest "terrane-format") coreTests)}
    ${builtins.concatStringsSep "\n" (map (runTest "terrane-sdk") nativeTests)}
    ${builtins.concatStringsSep "\n" (map runRetainedTest retainedTests)}
    printf 'PASS: 34 named common Memo replay, native persistence and conditional retention cases\n' > "$out/result"
  '';
}

{sourceGate, ...}: let
  collectorTests = [
    "gc::journal::tests::canonical_journals_preserve_exact_owner_and_reject_reincarnation"
    "gc::journal::tests::recovery_progress_preserves_immutable_authorization_across_new_epoch"
    "gc::journal::tests::authorization_rejects_association_wait_and_witness_changes"
    "gc::journal::tests::field_combinations_and_noncanonical_encodings_fail_closed"
    "gc::journal::tests::operation_truncation_and_cancellation_preserve_exact_intent"
    "gc::journal::tests::new_intent_lease_does_not_rewrite_existing_exclusion_epoch"
    "gc::journal::golden_tests::gc_local_v1_golden_journals_preserve_registered_bytes_and_field_bounds"
    "gc::journal::golden_tests::gc_local_v1_golden_operations_preserve_authorization_and_distinct_epochs"
    "gc::records::tests::gc_checkpoint_roots_roundtrip_every_closed_reason_and_optional_cutoff"
    "gc::records::tests::gc_checkpoint_mark_reconstructs_registered_hint_and_requires_exact_lookup"
    "gc::records::tests::gc_checkpoint_state_preserves_frontier_flags_and_broader_commit_contexts"
    "gc::records::tests::gc_checkpoint_decoders_reject_every_truncated_prefix"
    "gc::records::tests::gc_checkpoint_wire_rejects_incomplete_arrays_and_invalid_frontier_flags"
    "gc::records::context_tests::gc_context_legacy_empty_state_keeps_exact_bytes"
    "gc::records::context_tests::gc_context_checkpoint_same_identity_stays_distinct_and_cutoff_is_not_unique_key"
    "gc::records::context_tests::gc_context_cutoff_dominance_never_crosses_occurrences_or_legacy_context"
    "gc::records::context_tests::gc_context_absolute_paths_and_graft_occurrences_are_canonical"
    "gc::records::context_tests::gc_context_wire_rejects_explicit_null_wrong_tuple_and_noncanonical_path"
    "gc::windows::tests::gc_windows_compare_strict_grace_and_inclusive_deletion_without_overflow"
    "gc::windows::tests::gc_retains_uses_log_commit_and_lease_times_for_their_registered_modes"
    "gc::windows::tests::gc_tombstone_matches_bucket_codec_and_independent_registered_map"
    "gc::windows::tests::gc_checkpoint_integrity_digest_uses_raw_blake3_without_content_domain"
    "gc::mark::tests::gc_mark_reachability_revisits_shared_commits_under_broader_retention"
    "gc::mark::tests::gc_mark_checkpoint_filter_never_hides_exact_sorted_hashes"
    "gc::retention::tests::gc_roots_retention_resolves_root_values_and_ref_override"
    "gc::retention::tests::gc_retention_count_zero_and_overrides_have_distinct_selection"
    "gc::retention::tests::gc_retention_rejects_duplicate_properties_and_raises_default_to_window_minimum"
  ];

  retirementTests = [
    "gc::retirement::tests::authorization::permanent_authorizations_match_independent_disjoint_v2_bytes"
    "gc::retirement::tests::authorization::sweep_requires_initial_remote_artifacts_witness_and_full_checked_waits"
    "gc::retirement::tests::authorization::copied_retirement_requires_new_backend_matched_barrier_and_zero_removed_entries"
    "gc::retirement::tests::authorization::copied_preparation_is_disjoint_and_renewal_preserves_exact_plan"
    "gc::retirement::tests::progress::permanent_owner_selectors_match_independent_bytes_and_exact_pack_keys"
    "gc::retirement::tests::progress::permanent_operations_have_no_done_and_preserve_authorization_owner_forever"
    "gc::retirement::tests::progress::permanent_pass_matches_independent_bytes_and_requires_whole_owner_state"
    "gc::retirement::tests::progress::permanent_observations_use_unsigned_fieldwise_order_and_actual_instance_bounds"
    "gc::retirement::tests::progress::completed_pass_preserves_deferred_duties_and_requires_all_prior_plans_resolved"
    "gc::retirement::tests::progress::empty_completed_pass_starts_another_pass_and_checked_counters_never_wrap"
    "gc::retirement::tests::progress::permanent_pass_rejects_oversized_unknown_and_wrong_coverage_shapes"
    "gc::retirement::tests::fence::permanent_fences_match_independent_bytes_and_keep_copy_data_separate"
    "gc::retirement::tests::fence::copied_fence_rejects_unknown_inventory_burn_disagreement_and_wrong_stamps"
    "gc::retirement::tests::fence::fence_pointer_checks_raw_bytes_and_predecessor_not_future_selecting_slot"
    "bucket::records::burn_tests::generation_burns_preserve_legacy_bytes_and_known_empty_distinction"
    "bucket::records::burn_tests::generation_burns_are_unsigned_unique_and_never_removed_or_replaced"
    "gc::publication::cbor::tests::retirement::publication_burn_owner_key7_preserves_legacy_and_known_empty_bytes"
    "gc::publication::cbor::tests::retirement::permanent_retirement_proof_case3_has_independent_shape_and_no_copy_lineage_guess"
    "gc::publication::cbor::tests::retirement::case3_promotes_copied_visibility_once_and_all_later_proofs_preserve_owner"
    "gc::publication::cbor::tests::retirement::selected_v2_preparation_checks_whole_plan_key_and_preserves_portable_exclusion"
    "gc::publication::cbor::tests::retirement::selected_permanent_progress_keeps_owner_and_uses_fresh_transaction_pass_nonce"
  ];

  allocationTests = [
    "gc::retirement::tests::fence::fence_inventory_headers_do_not_reserve_storage_before_validating_rows"
    "gc::retirement::tests::fence::fence_ref_rows_validate_names_order_and_current_records_before_growing_inventory"
    "bucket::records::burn_tests::generation_burn_headers_validate_ids_before_growing_storage"
    "gc::publication::cbor::tests::retirement::publication_burn_owner_headers_validate_rows_before_growing_storage"
  ];

  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';
in {
  canonical-cbor = sourceGate "canonical-cbor" ''
    cd crates
    ${runTests "cbor::tests"}
    ${runTests "gc::lease::tests"}
    ${runTests "tree_format::tests::golden_leaf_round_trips_byte_exactly -- --exact"}
    ${runTests "indexing::carrier_tests::contextual_carriers_preserve_object_targets_and_role_shapes -- --exact"}
    ${runTests "indexing::carrier_tests::structural_index_names_do_not_become_value_inputs -- --exact"}
    ${runTests "indexing::carrier_tests::gap_bindings_require_primary_root_placement_and_exact_wrapper -- --exact"}
    ${builtins.concatStringsSep "\n" (map (test: runTests "${test} -- --exact") collectorTests)}
    ${builtins.concatStringsSep "\n" (map (test: runTests "${test} -- --exact") retirementTests)}

    # Bound only the actual test process, after compilation. A malformed count
    # must yield its typed row error rather than reserve gigabytes first.
    cargo test --frozen --offline -p terrane-core --lib --no-run --message-format=json \
      > "$TMPDIR/core-test-artifacts.jsonl"
    python3 - "$TMPDIR/core-test-artifacts.jsonl" > "$TMPDIR/core-test-executable" <<'PYTEST'
    import json
    import sys

    executables = set()
    with open(sys.argv[1], encoding="utf-8") as artifacts:
        for line in artifacts:
            artifact = json.loads(line)
            if (artifact.get("reason") == "compiler-artifact"
                    and artifact.get("profile", {}).get("test")
                    and artifact.get("target", {}).get("name") == "terrane_core"
                    and artifact.get("executable")):
                executables.add(artifact["executable"])

    if len(executables) != 1:
        raise SystemExit("expected one compiled terrane-core test executable")
    print(next(iter(executables)))
    PYTEST
    core_test_executable=$(cat "$TMPDIR/core-test-executable")
    run_bounded_test() {
      (
        ulimit -v 262144
        export MALLOC_ARENA_MAX=2
        "$core_test_executable" "$1" --exact --test-threads=1 > "$TMPDIR/test.log"
      )
      python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. 1 passed; 0 failed", output))' "$TMPDIR/test.log"
    }
    ${builtins.concatStringsSep "\n" (map (test: "run_bounded_test ${test}") allocationTests)}
    printf 'PASS: canonical CBOR, permanent retirement formats and bounded decoding\n' > "$out/result"
  '';

  tree-well-formed = sourceGate "tree-well-formed" ''
    cd crates
    ${runTests "tree_format::tests"}
    printf 'PASS: tree node and entry validation\n' > "$out/result"
  '';
}

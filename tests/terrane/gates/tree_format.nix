{sourceGate, ...}: let
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

{sourceGate, ...}: let
  focusedTest = ''
    run_ref_test() {
      test_name=$1
      cargo test --frozen --offline -p terrane --features tokio --lib -- --list > "$TMPDIR/ref-tests.txt"
      python3 - "$TMPDIR/ref-tests.txt" "$test_name" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    if f"{sys.argv[2]}: test" not in names:
        raise SystemExit(f"required reference test is missing: {sys.argv[2]}")
    PYTEST
      cargo test --frozen --offline -p terrane --features tokio --lib "$test_name" -- --exact
    }
  '';
in {
  ref-advance-ordering = sourceGate "ref-advance-ordering" ''
    cd crates
    ${focusedTest}
    run_ref_test ref_advance::tests::ref_advance_ordering_survives_reopen_with_exact_log_and_commit
    run_ref_test ref_advance::tests::notes_sidecars_refuse_branch_sessions_and_policy_advances
    run_ref_test ref_advance::fault_tests::ref_advance_ordering_pack_index_or_log_failure_never_publishes_head
    run_ref_test ref_advance::fault_tests::final_cas_directory_failure_is_indeterminate_and_fences_the_writer
    run_ref_test ref_advance::fault_tests::abandoned_durable_candidate_does_not_block_a_reopened_writer
    run_ref_test ref_advance::fault_tests::ref_advance_ordering_cancelled_held_publication_releases_independent_writer
    run_ref_test ref_advance::fault_tests::missing_secure_entropy_never_publishes_a_candidate_or_head
    run_ref_test ref_advance::fault_tests::unavailable_admin_policy_read_never_falls_back_or_publishes_objects
    run_ref_test ref_advance::fault_tests::captured_admin_request_preserves_unavailable_current_policy
    run_ref_test ref_advance::tests::revoked_current_admin_denies_acl_restore_but_preserves_commit_only_publication
    run_ref_test ref_advance::consumed_tests::held_consumed_resolver_records_exact_original_rows_and_canonical_policy
    run_ref_test ref_advance::consumed_tests::actual_guard_installation_rechecks_used_registration_after_slot_staging
    run_ref_test ref_advance::fault_tests::ordinary_advance_rechecks_used_registration_before_retained_slot_dispatch
    run_ref_test ref_advance::consumed_tests::stored_advance_methods_preserve_send_only_clock_and_unsupported_setup_has_no_effects
    run_ref_test ref_advance::tests::rollback_is_an_ordinary_selected_advance_to_an_earlier_commit
    run_ref_test ref_advance::tests::source_scoped_tag_only_authority_creates_signed_immutable_tags
    run_ref_test ref_advance::consumed_tests::empty_tree_tag_retains_actual_view_root_authorization
    printf 'PASS: durable publication ordering and explicit indeterminate CAS outcomes\n' > "$out/result"
  '';

  ref-epoch-fencing = sourceGate "ref-epoch-fencing" ''
    cd crates
    ${focusedTest}
    run_ref_test ref_advance::tests::ref_epoch_fencing_requires_a_new_session_after_conflict
    run_ref_test ref_advance::tests::multiwriter_rebases_with_ordered_verified_core_merge_and_source_receipts
    run_ref_test ref_advance::join_tests::explicit_multiwriter_merges_complete_after_actual_publication_races
    run_ref_test bucket::tests::ref_successors_fence_epoch_home_and_sequence
    run_ref_test bucket::tests::whole_record_cas_has_one_winner_across_independent_opens
    printf 'PASS: incremented writer epochs and exact-record concurrent CAS fencing\n' > "$out/result"
  '';

  ref-watch = sourceGate "ref-watch" ''
    cd crates
    ${focusedTest}
    run_ref_test ref_advance::tests::ref_watch_emits_current_then_waits_and_fills_every_committed_sequence
    run_ref_test bucket::tests::missing_reflog_with_committed_horizon_is_corruption
    run_ref_test bucket::tests::committed_reflog_must_match_the_complete_ref_record
    printf 'PASS: current-first live watch and committed reflog gap validation\n' > "$out/result"
  '';

  commit-order = sourceGate "commit-order" ''
    cd crates
    ${focusedTest}
    run_ref_test ref_advance::tests::ref_advance_ordering_survives_reopen_with_exact_log_and_commit
    run_ref_test ref_advance::fault_tests::ref_advance_ordering_pack_index_or_log_failure_never_publishes_head
    run_ref_test ref_advance::fault_tests::final_cas_directory_failure_is_indeterminate_and_fences_the_writer
    run_ref_test ref_advance::attribute_tests::commit_requirements_use_only_authenticated_readable_side_records
    run_ref_test ref_advance::tests::private_local_bootstrap_uses_configured_acl_domain_and_profile
    run_ref_test ref_advance::domain_tests::implicit_domain_uses_immutable_root_and_edits_preserve_explicit_owner
    run_ref_test ref_advance::domain_tests::initial_domain_caveats_use_physical_scope_and_actual_candidate_domain
    run_ref_test ref_advance::domain_tests::unsupported_effective_store_is_rejected_before_any_publication
    run_ref_test ref_advance::domain_tests::initial_commit_grant_narrows_bootstrap_admin_without_extra_admin
    run_ref_test ref_advance::domain_tests::introduced_child_delegation_uses_its_actual_ancestor_acl
    run_ref_test ref_advance::read_tests::child_acl_change_accepts_current_admin_on_its_actual_ancestor
    run_ref_test ref_advance::join_tests::keep_conflict_admits_verified_base_and_both_candidate_references
    printf 'PASS: actual durable pack/index/commit/log/ref publication order\n' > "$out/result"
  '';
}

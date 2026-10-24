{
  nativeSdkGate,
  localTwoPhaseGc,
  ...
}: let
  nativeTests = [
    "guard::original::control::lock_mode_tests::original_retained_readers_refuse_actual_writer_and_release_namespace"
    "guard::original::control::lock_mode_tests::original_read_and_write_attempts_refuse_live_writer_without_waiting"
    "gc::lease::tests::native_gc_independent_collectors_have_one_selected_winner"
    "gc::lease::tests::native_gc_renewal_uses_exact_whole_value_and_increases_revision"
    "gc::lease::tests::native_gc_live_other_holder_refuses_without_cache_repair_or_effects"
    "gc::lease::tests::native_gc_expired_lease_takeover_selects_a_higher_epoch"
    "gc::lease::tests::native_gc_queued_expiry_refuses_before_selected_slot_syscall"
    "gc::lease::tests::native_gc_queued_consumed_control_change_refuses_before_syscall"
    "gc::lease::tests::native_gc_queued_predecessor_change_refuses_before_syscall"
    "gc::lease::tests::native_gc_cancelled_waiter_retains_all_exclusions_through_slot_sync"
    "gc::lease::tests::native_gc_queued_renewal_requires_the_original_expiry_to_remain_live"
    "gc::lease::tests::native_gc_queued_clock_discontinuity_refuses_before_syscall"
    "gc::lease::tests::native_gc_stale_configured_guard_refuses_without_effects"
    "gc::lease::tests::native_gc_existing_open_does_not_recreate_coordination_or_control"
    "gc::lease::tests::native_gc_final_selection_ack_requires_current_retained_clock"
    "gc::runner::tests::gc_native_published_roots_mark_finish_and_resume"
    "gc::runner::tests::gc_native_stale_runner_renewal_stops_before_checkpoint_effects"
    "gc::runner::tests::gc_native_canceled_checkpoint_keeps_exclusion_and_poisons_session"
    "gc::runner::tests::gc_native_queued_checkpoint_rechecks_actual_expiry_and_never_acknowledges"
    "gc::runner::tests::gc_native_takeover_refuses_old_mark_epoch_and_completes_new_cycle"
  ];

  localTests = [
    "gc::lease::local_tests::native_gc_rc_bindings_acquire_renew_take_over_and_reopen"
  ];

  rootTests = [
    "gc::lease::tests::empty_roots::native_gc_known_empty_inventory_completes_empty_root_collection"
    "gc::runner::walk::tests::native::gc_roots_native_current_inventory_keeps_all_commit_classes_and_live_jobs"
    "gc::runner::walk::tests::native::gc_roots_native_incomplete_inventory_cannot_replace_selected_authority"
    "gc::runner::walk::tests::native::gc_roots_native_retained_selection_keeps_absent_history_and_excludes_proposals"
    "gc::runner::walk::tests::native::gc_roots_native_snapshot_resume_preserves_roots_after_current_ref_moves"
    "gc::runner::tests::current_roots::gc_current_native_keeps_opaque_notes_absent_history_and_guard_record"
  ];

  graceTests = [
    "gc::runner::tests::retirement::gc_requested_retirement_preserves_marking_grace_and_exact_candidate_scope"
    "gc::runner::tests::retirement::gc_initial_retirement_native_grace_uses_pair_backend_upper_bound"
    "gc::runner::tests::retirement::gc_initial_retirement_native_newer_index_controls_pair_grace"
    "gc::runner::tests::retirement::gc_initial_retirement_native_refuses_unenforced_commit_window_before_effects"
    "gc::runner::tests::retirement::gc_initial_retirement_native_selects_exact_exclusion_then_committed_trash"
  ];

  markTests = [
    "gc::runner::tests::inspection::gc_metadata_pack_sharing_preserves_consumed_identities_and_fresh_store_reads"
    "gc::runner::tests::inspection::gc_metadata_pack_sharing_keeps_membership_and_restore_checks_independent"
    "gc::runner::tests::inspection::gc_metadata_pack_sharing_rejects_changed_payload_before_native_handoff"
    "gc::runner::tests::inspection::gc_metadata_pack_sharing_preserves_session_and_original_refusal"
    "gc::runner::tests::inspection::catalog_sharing::gc_catalog_sharing_reuses_artifacts_without_reusing_member_checks"
    "gc::runner::tests::inspection::catalog_sharing::gc_catalog_sharing_refuses_changed_artifacts_at_native_handoff"
    "gc::runner::tests::inspection::catalog_sharing::gc_catalog_sharing_preserves_session_original_and_restore_checks"
    "gc::runner::tests::inspection::catalog_concurrency::gc_catalog_sharing_retains_concurrent_miss_preimages"
    "gc::runner::walk::tests::common_walk_certificates_apply_only_to_direct_entry_objects"
    "gc::runner::walk::tests::common_walk_context_order_is_fieldwise_and_round_trips_exact_state"
    "gc::runner::walk::tests::common_walk_cutoffs_remain_per_occurrence_and_broadest"
    "gc::runner::walk::tests::common_walk_empty_physical_node_keeps_ordinary_and_index_roles_distinct"
    "gc::runner::walk::tests::common_walk_selects_complete_graft_key_and_refuses_forged_position"
    "gc::runner::walk::tests::common_walk_witness_and_legacy_rows_do_not_cover_full_present_context"
    "gc::runner::walk::tests::native::gc_common_walk_native_attributes_retain_versions_without_discovery_roots"
    "gc::runner::walk::tests::native::gc_common_walk_native_complete_checkpoint_reopens_and_preserves_contextual_marks"
    "gc::runner::walk::tests::native::gc_common_walk_native_broader_cutoff_reuses_full_occurrence_expansion"
    "gc::runner::walk::tests::native::gc_common_walk_native_recorded_preservation_keeps_inert_index_bindings"
    "gc::runner::walk::tests::native::gc_common_walk_native_independently_rooted_source_keeps_own_producer_context"
    "gc::runner::walk::tests::native::overlays::signed_overlay_layer_ancestry_survives_collection_and_reopen"
    "gc::runner::walk::tests::native::overlays::signed_overlay_layer_default_and_forged_context_are_refused"
    "gc::runner::walk::tests::native::overlays::indexed_signed_overlay_layer_replays_exact_output"
    "gc::runner::walk::tests::native::gc_common_walk_native_indexes_preserve_exact_auxiliary_roles"
    "gc::runner::walk::tests::native::gc_common_walk_native_invalid_matching_attribution_keeps_frontier_unchanged"
    "gc::runner::walk::tests::native::gc_common_walk_native_manifest_dictionary_and_legacy_records_keep_declared_edges"
    "gc::runner::walk::tests::native::gc_common_walk_native_repeated_occurrences_cut_erased_audit_sources_only"
    "gc::runner::walk::tests::native::gc_common_walk_native_witness_then_full_keeps_declared_chunks_without_body_reads"
  ];

  # An exact filter with no matching test succeeds in Cargo. Validate the whole
  # required inventory before running each actual case in its own process.
  focusedTests = features: tests: ''
    cargo test --frozen --offline -p terrane-sdk --no-default-features \
      --features ${features} --lib -- --list > "$TMPDIR/gc-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/gc-tests.txt" '${builtins.toJSON tests}'

    for test_name in ${builtins.concatStringsSep " " tests}; do
      if ! cargo test --frozen --offline -p terrane-sdk --no-default-features \
        --features ${features} --lib "$test_name" -- --exact \
        > "$TMPDIR/gc-test.log" 2>&1; then
        cat "$TMPDIR/gc-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/gc-test.log" "[\"$test_name\"]"
    done
  '';

  nativeFocusedTests = label: selectors:
    import ../_native-cases.nix {
      inherit label selectors;
      enterCrates = false;
    };
in {
  gc-two-phase-delete = localTwoPhaseGc;

  gc-grace-window = nativeSdkGate "gc-grace-window" ''
    cd crates
    ${nativeFocusedTests "gc-grace-window" graceTests}
    printf 'PASS: actual pack/index timestamps, requested candidate scope, strict grace boundary and enforced commit window (5 exact cases)\n' \
      > "$out/result"
  '';

  gc-roots-complete = nativeSdkGate "gc-roots-complete" ''
    cd crates
    ${nativeFocusedTests "gc-roots-complete" rootTests}
    printf 'PASS: native selected root inventory, known empty roots, retention, opaque Notes and snapshot continuity (6 exact cases)\n' \
      > "$out/result"
  '';

  gc-mark-reachability = nativeSdkGate "gc-mark-reachability" ''
    cd crates
    ${nativeFocusedTests "gc-mark-reachability" markTests}
    printf 'PASS: contextual metadata marking, independent producers, certified edges and native replay (${toString (builtins.length markTests)} exact cases)\n' \
      > "$out/result"
  '';

  gc-singleton-lease = nativeSdkGate "gc-singleton-lease" ''
    cd crates
    ${nativeFocusedTests "gc-singleton-lease" nativeTests}
    ${focusedTests "std,surface-sdk" localTests}
    printf 'PASS: selected singleton lease, administrative exclusion, runner fencing, takeover and non-Send bindings (21 exact cases)\n' \
      > "$out/result"
  '';
}

{
  sourceGate,
  prerequisites,
}: let
  selectors = [
    "gc::runner::tests::retirement::gc_initial_retirement_native_selects_exact_exclusion_then_committed_trash"
    "gc::runner::tests::retirement::gc_initial_retirement_native_grace_uses_pair_backend_upper_bound"
    "gc::runner::tests::retirement::gc_initial_retirement_native_refuses_unenforced_commit_window_before_effects"
    "gc::runner::tests::retirement::gc_initial_retirement_native_unknown_creator_never_mints_trash"
    "gc::runner::tests::retirement::gc_initial_retirement_native_barrier_requires_actual_closed_acknowledgment"
    "gc::runner::tests::retirement::gc_initial_retirement_native_trash_faults_keep_exclusion_without_acknowledgment"
    "gc::runner::tests::retirement::gc_initial_retirement_native_prior_cycle_history_refuses_missing_old_artifacts"
    "gc::runner::tests::retirement::gc_initial_retirement_native_refreshes_clock_after_barrier_directory_sync"
    "gc::runner::tests::retirement::gc_initial_retirement_native_cancellation_retains_exclusion_until_worker_finishes"
    "gc::runner::tests::retirement::gc_initial_retirement_native_prior_trash_or_journal_refuses_before_exclusion"
    "gc::runner::tests::retirement::gc_initial_retirement_native_newer_index_controls_pair_grace"
    "gc::runner::tests::source_carry::post_done::ordinary::ordinary_source_and_original_survive_done_reopen_and_zero_node_cold_fork"
    "gc::runner::tests::source_carry::post_done::imported::foreign_used_view_and_original_survive_done_reopen_and_zero_node_cold_fork"
    "gc::runner::tests::source_carry::post_done::ordinary::consumed_original_reincarnation_after_done_refuses_cold_publication_without_tree_io"
  ];
in
  # This check proves ordinary local-v1 only. Copied and remote permanent
  # ownership remain separate requirements of the full two-phase deletion gate.
  sourceGate "native-local-gc-conformance" ''
    for prerequisite in ${builtins.concatStringsSep " " (map toString prerequisites)}; do
      test -s "$prerequisite/result"
    done
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$TMPDIR/local-gc-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/local-gc-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$TMPDIR/local-gc-test.log" 2>&1; then
        cat "$TMPDIR/local-gc-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/local-gc-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: ordinary local-v1 retirement and post-Done reuse (14 exact cases), with physical recovery and current qualification prerequisites\n' \
      > "$out/result"
  ''
